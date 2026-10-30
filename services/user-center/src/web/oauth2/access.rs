//! Interactive recovery for missing application entitlement. Silent requests never enter here.
use axum::{
    Form,
    extract::{Query, State},
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::CookieJar;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    db::entity::{apps, authorization_requests, oauth_clients, users},
    state::app::AppState,
    web::{error::OAuthError, session::extract_session, util},
};

#[derive(Serialize, Deserialize)]
struct Recovery {
    request_id: Uuid,
    session_id: Uuid,
}
#[derive(Deserialize)]
pub struct Params {
    #[serde(default)]
    token: String,
}
#[derive(Deserialize)]
pub struct Input {
    csrf_token: String,
    token: String,
    action: String,
}
fn key(state: &AppState) -> &[u8] {
    state
        .config
        .sso
        .cookie_signing_secret
        .expose_secret()
        .as_bytes()
}

pub(super) fn redirect(
    state: &AppState,
    jar: CookieJar,
    request_id: Uuid,
    session_id: Uuid,
) -> Result<(CookieJar, Response), OAuthError> {
    let token = pero_utils::crypto::encode_signed_json(
        &Recovery {
            request_id,
            session_id,
        },
        key(state),
    )
    .map_err(|_| OAuthError::Unavailable)?;
    let mut url = "/oauth2/authorize/access".to_owned();
    pero_utils::encode::append_query_param(&mut url, "token", &token);
    Ok((jar, Redirect::to(&url).into_response()))
}

async fn load(
    state: &AppState,
    jar: &CookieJar,
    token: &str,
) -> Result<authorization_requests::Model, OAuthError> {
    let recovery: Recovery = pero_utils::crypto::decode_signed_json(token, key(state))
        .map_err(|_| OAuthError::BadRequest("Invalid recovery request".into()))?;
    let session = extract_session(state, jar)
        .await
        .map_err(|_| OAuthError::Unavailable)?;
    if session.as_ref().map(|s| s.id) != Some(recovery.session_id) {
        return Err(OAuthError::BadRequest(
            "Recovery session changed or expired".into(),
        ));
    }
    authorization_requests::Entity::find_by_id(recovery.request_id)
        .one(&state.db)
        .await
        .map_err(|_| OAuthError::Unavailable)?
        .ok_or(OAuthError::BadRequest(
            "Authorization request not found".into(),
        ))
}
fn available(request: &authorization_requests::Model) -> bool {
    request.completed_at.is_none() && request.expires_at > time::OffsetDateTime::now_utc()
}
fn expired(state: &AppState, jar: CookieJar) -> Response {
    state
        .web_security()
        .view_with_csrf(jar, "AppAccessDeniedView", |csrf_token| {
            serde_json::json!({
                "csrf_token": csrf_token, "token": "", "app_name": "", "username": "",
                "system": false, "expired": true,
            })
        })
}

pub async fn get(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(params): Query<Params>,
) -> Response {
    let request = match load(&state, &jar, &params.token).await {
        Ok(r) => r,
        Err(OAuthError::BadRequest(_)) => return expired(&state, jar),
        Err(e) => return e.into_response(),
    };
    if !available(&request) {
        return expired(&state, jar);
    }
    let app = match apps::Entity::find_by_id(request.app_id)
        .one(&state.db)
        .await
    {
        Ok(Some(a)) => a,
        Ok(None) => return expired(&state, jar),
        Err(e) => return util::dependency_error(e),
    };
    let session = match extract_session(&state, &jar).await {
        Ok(Some(s)) => s,
        Ok(None) => return expired(&state, jar),
        Err(e) => return e.into_response(),
    };
    let user = match users::Entity::find_by_id(session.user_id)
        .one(&state.db)
        .await
    {
        Ok(Some(u)) => u,
        Ok(None) => return expired(&state, jar),
        Err(e) => return util::dependency_error(e),
    };
    state
        .web_security()
        .view_with_csrf(jar, "AppAccessDeniedView", |csrf_token| {
            serde_json::json!({
                "csrf_token": csrf_token, "token": params.token, "app_name": app.name,
                "username": user.username, "system": app.system, "expired": false,
            })
        })
}

pub async fn post(
    State(state): State<AppState>,
    jar: CookieJar,
    Form(input): Form<Input>,
) -> Response {
    if let Some(e) = util::verify_csrf_or_json_error(&jar, &input.csrf_token, &state) {
        return e;
    }
    if !matches!(input.action.as_str(), "retry" | "other" | "cancel") {
        return pero_api_axum::json_error("invalid_request");
    }
    let request = match load(&state, &jar, &input.token).await {
        Ok(r) => r,
        Err(OAuthError::BadRequest(_)) => return expired(&state, jar),
        Err(e) => return e.into_response(),
    };
    if !available(&request) {
        return expired(&state, jar);
    }
    if input.action == "cancel" {
        let result = authorization_requests::Entity::update_many()
            .col_expr(
                authorization_requests::Column::CompletedAt,
                sea_orm::sea_query::Expr::value(time::OffsetDateTime::now_utc()),
            )
            .filter(authorization_requests::Column::Id.eq(request.id))
            .filter(authorization_requests::Column::CompletedAt.is_null())
            .exec(&state.db)
            .await;
        return match result {
            Ok(_) => Redirect::to("/account/profile").into_response(),
            Err(e) => util::dependency_error(e),
        };
    }
    // Validate current client configuration before resuming a pending request.
    let result = async {
        let client = oauth_clients::Entity::find_by_id(request.client_id)
            .one(&state.db)
            .await
            .map_err(|_| OAuthError::Unavailable)?
            .ok_or(OAuthError::BadRequest("Client not found".into()))?;
        let oauth = state.oauth_service();
        let client = oauth
            .validate_client(&client.identifier, &request.redirect_uri, &request.scopes)
            .await?;
        oauth.validate_app(&client).await?;
        if client.app_id != request.app_id
            || ((client.require_pkce || client.r#type == crate::db::enums::OauthClientType::Public)
                && request.code_challenge.is_none())
        {
            return Err(OAuthError::BadRequest(
                "Client configuration changed".into(),
            ));
        }
        if !client.grant_types.iter().any(|g| g == "authorization_code") {
            return Err(OAuthError::BadRequest(
                "Authorization code grant is disabled".into(),
            ));
        }
        if input.action == "other" {
            let jar = super::select_account::switch(&state, jar.clone())
                .await
                .map_err(|_| OAuthError::Unavailable)?;
            super::authorize::pending_redirect(&state, &jar, request.id).await
        } else {
            super::authorize::resolve_authorization(&state, &jar, &request).await
        }
    }
    .await;
    match result {
        Ok(v) => v.into_response(),
        Err(OAuthError::BadRequest(_)) => expired(&state, jar),
        Err(e) => e.into_response(),
    }
}
