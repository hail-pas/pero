use askama::Template;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

use crate::domain::identity::session;
use crate::handler::account::common;
use crate::handler::account::common::{AccountLayout, SessionView};
use crate::shared::constants::cookies::ACCOUNT_TOKEN;
use crate::shared::error::AppError;
use crate::shared::state::AppState;
use crate::shared::utils::extract_cookie;

#[derive(Template, Debug)]
#[template(path = "account/sessions.html")]
pub struct SessionsTemplate {
    pub layout: AccountLayout,
    pub sessions: Vec<SessionView>,
}

#[derive(Debug, Deserialize)]
pub struct DeleteSessionForm {
    pub session_id: String,
}

pub async fn sessions_get(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let user = common::get_account_user(&state, &headers).await?;
    let views = build_session_views(&state, user.id, &headers).await?;
    let tpl = SessionsTemplate {
        layout: AccountLayout::new("sessions", &user),
        sessions: views,
    };
    Ok(common::render_tpl(&tpl)?.into_response())
}

pub async fn delete_session_post(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Form(form): axum::Form<DeleteSessionForm>,
) -> Result<Response, AppError> {
    let _user_id = common::get_account_user_id(&state, &headers).await?;
    if current_session_id_from_cookie(&headers).as_deref() == Some(form.session_id.as_str()) {
        return Err(AppError::BadRequest(
            "Cannot terminate current session.".into(),
        ));
    }

    session::revoke_session(&state.cache, &form.session_id).await?;
    Ok(axum::Json(crate::api::response::MessageResponse::success(
        "Session terminated.",
    ))
    .into_response())
}

pub async fn delete_all_post(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let user_id = common::get_account_user_id(&state, &headers).await?;
    let all_ids = session::list_user_session_ids(&state.cache, user_id).await?;
    let current = current_session_id_from_cookie(&headers)
        .filter(|sid| all_ids.iter().any(|item| item == sid))
        .ok_or_else(|| AppError::BadRequest("Current session could not be identified.".into()))?;

    for sid in &all_ids {
        if sid != &current {
            if let Err(err) = session::revoke_session(&state.cache, sid).await {
                tracing::warn!(session_id = %sid, error = %err, "failed to revoke session");
            }
        }
    }

    Ok(axum::Json(crate::api::response::MessageResponse::success(
        "All other sessions terminated.",
    ))
    .into_response())
}

pub async fn logout_post(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    if let Some(token) = common::extract_cookie(&headers, ACCOUNT_TOKEN) {
        if let Ok(claims) = crate::infra::jwt::decode_token_claims_unverified(&token) {
            if let Some(ref sid) = claims.sid {
                let _ = session::revoke_session(&state.cache, sid).await;
            }
        }
    }

    let mut response = axum::Json(crate::api::response::MessageResponse::success(
        "Signed out.",
    ))
    .into_response();
    response.headers_mut().append(
        axum::http::header::SET_COOKIE,
        clear_account_cookie(&state)?,
    );
    Ok(response)
}

async fn build_session_views(
    state: &AppState,
    user_id: uuid::Uuid,
    headers: &HeaderMap,
) -> Result<Vec<SessionView>, AppError> {
    let current = current_session_id_from_cookie(headers);
    let session_ids = session::list_user_session_ids(&state.cache, user_id).await?;
    let mut views = Vec::new();

    for sid in &session_ids {
        if let Some(s) = session::get_session(&state.cache, sid).await? {
            views.push(SessionView {
                id: sid.clone(),
                session_id: short_session_id(sid),
                device: s.device.clone(),
                location: s.location.clone(),
                created_at: fmt_ts(s.created_at),
                current: current.as_deref() == Some(sid.as_str()),
                expired: false,
            });
        }
    }

    Ok(views)
}

fn short_session_id(session_id: &str) -> String {
    if session_id.len() > 12 {
        format!(
            "{}...{}",
            &session_id[..8],
            &session_id[session_id.len() - 4..]
        )
    } else {
        session_id.to_owned()
    }
}

fn current_session_id_from_cookie(headers: &HeaderMap) -> Option<String> {
    let token = extract_cookie(headers, ACCOUNT_TOKEN)?;
    crate::infra::jwt::decode_token_claims_unverified(&token)
        .ok()?
        .sid
}

fn clear_account_cookie(state: &AppState) -> Result<axum::http::HeaderValue, AppError> {
    crate::handler::sso::common::build_cookie(ACCOUNT_TOKEN, "", &state.config.sso, 0)
}

fn fmt_ts(ts: i64) -> String {
    chrono::DateTime::from_timestamp(ts, 0)
        .map(|dt| dt.format("%Y-%m-%d %H:%M").to_string())
        .unwrap_or_default()
}
