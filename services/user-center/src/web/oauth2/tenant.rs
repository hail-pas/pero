//! Signed, session-bound choice for multi-workspace OAuth grants.
use crate::{
    db::entity::authorization_requests,
    service::{access, tenant_context},
    state::{app::AppState, session::SsoSession},
    web::{error::OAuthError, session::extract_session, util},
};
use axum::{
    Form,
    extract::{Query, State},
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::CookieJar;
use sea_orm::{ConnectionTrait, EntityTrait};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Serialize, Deserialize)]
struct Ticket {
    tenant_choice_request_id: Uuid,
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
            tenant_choice_request_id: request_id,
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
) -> Result<(SsoSession, authorization_requests::Model), Box<Response>> {
    let ticket: Ticket = pero_utils::crypto::decode_signed_json(token, key(s))
        .map_err(|_| pero_api_axum::json_error("invalid_request"))?;
    let session = extract_session(s, jar)
        .await
        .map_err(IntoResponse::into_response)?
        .ok_or_else(|| Redirect::to("/account/login").into_response())?;
    if session.id != ticket.session_id {
        return Err(Box::new(pero_api_axum::json_error("invalid_request")));
    }
    let req = authorization_requests::Entity::find_by_id(ticket.tenant_choice_request_id)
        .one(&s.db)
        .await
        .map_err(util::dependency_error)?
        .filter(|r| {
            r.tenant_id.is_none()
                && r.completed_at.is_none()
                && r.expires_at > time::OffsetDateTime::now_utc()
        })
        .ok_or_else(|| Box::new(pero_api_axum::json_error("invalid_request")))?;
    Ok((session, req))
}

async fn first_access<C: ConnectionTrait>(
    db: &C,
    session: &SsoSession,
    req: &authorization_requests::Model,
) -> Result<bool, sea_orm::DbErr> {
    Ok(req.diagnostic_session_id.is_none()
        && access::can_open_super_admin_access(db, session.user_id, req.app_id).await?)
}

pub async fn get(State(s): State<AppState>, jar: CookieJar, Query(p): Query<Params>) -> Response {
    let (session, req) = match load(&s, &jar, &p.token).await {
        Ok(v) => v,
        Err(e) => return *e,
    };
    let first_access = match first_access(&s.db, &session, &req).await {
        Ok(value) => value,
        Err(e) => return util::dependency_error(e),
    };
    let choices = match tenant_context::authorization_choices(
        &s.db,
        session.user_id,
        req.app_id,
        first_access,
    )
    .await
    {
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
        Err(e) => return *e,
    };
    let updated = match async {
        let txn = s
            .oauth_service()
            .begin_authorization_choice(&req, session.id, session.user_id)
            .await
            .map_err(super::authorize::pending_form_error)?;
        let context = if first_access(&txn, &session, &req)
            .await
            .map_err(util::dependency_error)?
        {
            tenant_context::eligible(&txn, session.user_id, req.app_id, p.tenant_id).await
        } else {
            tenant_context::active(&txn, session.user_id, req.app_id, p.tenant_id).await
        };
        if context.map_err(util::dependency_error)?.is_none() {
            return Err(Box::new(pero_api_axum::json_error("forbidden")));
        }
        let updated = crate::db::helper::auth_request::bind_tenant(&txn, req.id, p.tenant_id)
            .await
            .map_err(util::dependency_error)?
            .ok_or_else(|| Box::new(pero_api_axum::json_error("invalid_request")))?;
        txn.commit().await.map_err(util::dependency_error)?;
        Ok(updated)
    }
    .await
    {
        Ok(updated) => updated,
        Err(response) => return *response,
    };
    super::authorize::resolve_pending_authorization(&s, &jar, &updated, true)
        .await
        .into_response()
}
