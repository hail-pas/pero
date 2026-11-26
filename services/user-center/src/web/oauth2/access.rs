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
    service::{ManagementError, enrollment::ApplicationSource},
    state::app::AppState,
    web::{error::OAuthError, session::extract_session, util},
};

#[derive(Serialize, Deserialize)]
struct Recovery {
    source: ApplicationSource,
    session_id: Uuid,
    diagnostic: bool,
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
    request: &authorization_requests::Model,
    session_id: Uuid,
) -> Result<(CookieJar, Response), OAuthError> {
    let token = pero_utils::crypto::encode_signed_json(
        &Recovery {
            source: request.into(),
            session_id,
            diagnostic: request.diagnostic_session_id.is_some(),
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
) -> Result<
    (
        ApplicationSource,
        Uuid,
        Option<authorization_requests::Model>,
    ),
    OAuthError,
> {
    let recovery: Recovery = pero_utils::crypto::decode_signed_json(token, key(state))
        .map_err(|_| OAuthError::BadRequest("Invalid recovery request".into()))?;
    let session = extract_session(state, jar)
        .await
        .map_err(|_| OAuthError::Unavailable)?
        .filter(|s| s.id == recovery.session_id)
        .ok_or_else(|| OAuthError::BadRequest("Recovery session changed or expired".into()))?;
    let request = authorization_requests::Entity::find_by_id(recovery.source.request_id)
        .one(&state.db)
        .await
        .map_err(|_| OAuthError::Unavailable)?;
    Ok((recovery.source, session.user_id, request))
}
fn available(request: &authorization_requests::Model) -> bool {
    request.completed_at.is_none() && request.expires_at > time::OffsetDateTime::now_utc()
}

pub(crate) async fn enrollment_source(
    state: &AppState,
    token: &str,
    session_id: Uuid,
    app_id: Uuid,
) -> Result<Option<ApplicationSource>, ManagementError> {
    let Ok(recovery) = pero_utils::crypto::decode_signed_json::<Recovery>(token, key(state)) else {
        return Ok(None);
    };
    if recovery.session_id != session_id || recovery.source.app_id != app_id || recovery.diagnostic
    {
        return Ok(None);
    }
    // Keep the registered login entry even after cleanup removes the OAuth request.
    let client = oauth_clients::Entity::find_by_id(recovery.source.client_id)
        .one(&state.db)
        .await?;
    Ok(client
        .filter(|c| {
            c.app_id == app_id
                && c.status == crate::db::enums::CommonStatus::Active
                && c.login_uri
                    .as_deref()
                    .is_some_and(crate::service::client::valid_login_uri)
        })
        .map(|_| recovery.source))
}
fn expired(state: &AppState, jar: CookieJar, login_url: Option<String>) -> Response {
    state
        .web_security()
        .view_with_csrf(jar, "AppAccessDeniedView", |csrf_token| {
            serde_json::json!({
                "csrf_token": csrf_token, "token": "", "app_name": "", "username": "",
                "system": false, "expired": true, "login_url": login_url,
            })
        })
}

async fn expired_with_source(
    state: &AppState,
    jar: CookieJar,
    source: ApplicationSource,
) -> Response {
    let login_url = match oauth_clients::Entity::find_by_id(source.client_id)
        .one(&state.db)
        .await
    {
        Ok(Some(client)) if client.app_id == source.app_id => {
            crate::web::login_flow::client_login_target(state, client, source.tenant_id, None)
                .await
                .unwrap_or_default()
        }
        _ => None,
    };
    expired(state, jar, login_url)
}

pub async fn get(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(params): Query<Params>,
) -> Response {
    let (request, user_id) = match load(&state, &jar, &params.token).await {
        Ok((_, user_id, Some(r))) if available(&r) => (r, user_id),
        Ok((source, _, _)) => return expired_with_source(&state, jar, source).await,
        Err(OAuthError::BadRequest(_)) => return expired(&state, jar, None),
        Err(e) => return e.into_response(),
    };
    let app = match apps::Entity::find_by_id(request.app_id)
        .one(&state.db)
        .await
    {
        Ok(Some(a)) => a,
        Ok(None) => return expired(&state, jar, None),
        Err(e) => return util::dependency_error(e),
    };
    let user = match users::Entity::find_by_id(user_id).one(&state.db).await {
        Ok(Some(u)) => u,
        Ok(None) => return expired(&state, jar, None),
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
        Ok((_, _, Some(r))) if available(&r) => r,
        Ok((source, _, _)) => return expired_with_source(&state, jar, source).await,
        Err(OAuthError::BadRequest(_)) => return expired(&state, jar, None),
        Err(e) => return e.into_response(),
    };
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
        state
            .oauth_service()
            .validate_pending_authorization(&request)
            .await?;
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
        Err(OAuthError::BadRequest(_)) => expired(&state, jar, None),
        Err(e) => e.into_response(),
    }
}
