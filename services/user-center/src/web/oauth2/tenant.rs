//! Signed, session-bound choice for multi-workspace OAuth grants.
use crate::{
    db::entity::authorization_requests,
    state::{app::AppState, session::SsoSession},
    web::{error::OAuthError, session::extract_session, util},
};
use axum::{
    Form,
    extract::{Query, State},
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::CookieJar;
use sea_orm::EntityTrait;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Serialize, Deserialize)]
struct Ticket {
    request_id: Uuid,
    session_id: Uuid,
}
#[derive(Deserialize)]
pub struct Params {
    token: String,
}
#[derive(Deserialize)]
pub struct Choice {
    csrf_token: String,
    token: String,
    tenant_id: Uuid,
}
fn key(s: &AppState) -> &[u8] {
    s.config
        .sso
        .cookie_signing_secret
        .expose_secret()
        .as_bytes()
}
pub fn redirect(
    s: &AppState,
    jar: CookieJar,
    request_id: Uuid,
    session_id: Uuid,
) -> Result<(CookieJar, Response), OAuthError> {
    let token = pero_utils::crypto::encode_signed_json(
        &Ticket {
            request_id,
            session_id,
        },
        key(s),
    )
    .map_err(|_| OAuthError::Unavailable)?;
    let mut url = "/oauth2/authorize/tenant".to_owned();
    pero_utils::encode::append_query_param(&mut url, "token", &token);
    Ok((jar, Redirect::to(&url).into_response()))
}
async fn load(
    s: &AppState,
    jar: &CookieJar,
    token: &str,
) -> Result<(SsoSession, authorization_requests::Model), Response> {
    let ticket: Ticket = pero_utils::crypto::decode_signed_json(token, key(s))
        .map_err(|_| pero_api_axum::json_error("invalid_request"))?;
    let session = extract_session(s, jar)
        .await
        .map_err(IntoResponse::into_response)?
        .ok_or_else(|| Redirect::to("/account/login").into_response())?;
    if session.id != ticket.session_id {
        return Err(pero_api_axum::json_error("invalid_request"));
    }
    let req = authorization_requests::Entity::find_by_id(ticket.request_id)
        .one(&s.db)
        .await
        .map_err(util::dependency_error)?
        .filter(|r| {
            r.tenant_id.is_none()
                && r.completed_at.is_none()
                && r.expires_at > time::OffsetDateTime::now_utc()
        })
        .ok_or_else(|| pero_api_axum::json_error("invalid_request"))?;
    Ok((session, req))
}
pub async fn get(State(s): State<AppState>, jar: CookieJar, Query(p): Query<Params>) -> Response {
    let (session, req) = match load(&s, &jar, &p.token).await {
        Ok(v) => v,
        Err(e) => return e,
    };
    let choices =
        match crate::service::tenant_context::choices(&s.db, session.user_id, req.app_id).await {
            Ok(v) => v,
            Err(e) => return util::dependency_error(e),
        };
    s.web_security()
        .view_with_csrf(jar, "TenantChoiceView", |csrf_token| {
            serde_json::json!({
                "csrf_token":csrf_token,"token":p.token,"choices":choices
            })
        })
}
pub async fn post(State(s): State<AppState>, jar: CookieJar, Form(p): Form<Choice>) -> Response {
    if let Some(e) = util::verify_csrf_or_json_error(&jar, &p.csrf_token, &s) {
        return e;
    }
    let (session, req) = match load(&s, &jar, &p.token).await {
        Ok(v) => v,
        Err(e) => return e,
    };
    match crate::service::tenant_context::active(&s.db, session.user_id, req.app_id, p.tenant_id)
        .await
    {
        Ok(Some(_)) => {}
        Ok(None) => return pero_api_axum::json_error("forbidden"),
        Err(e) => return util::dependency_error(e),
    };
    // Consume the initial choice exactly once; concurrent submissions cannot rewrite its tenant.
    let updated =
        match crate::db::helper::auth_request::bind_tenant(&s.db, req.id, p.tenant_id).await {
            Ok(Some(request)) => request,
            Ok(None) => return pero_api_axum::json_error("invalid_request"),
            Err(error) => return util::dependency_error(error),
        };
    match super::authorize::resolve_authorization(&s, &jar, &updated).await {
        Ok(v) => v.into_response(),
        Err(e) => e.into_response(),
    }
}
