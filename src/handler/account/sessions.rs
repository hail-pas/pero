use askama::Template;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

use crate::domain::identity::session;
use crate::handler::account::common;
use crate::handler::account::common::{SessionView, user_display_name, user_initial};
use crate::shared::constants::cookies::ACCOUNT_TOKEN;
use crate::shared::error::AppError;
use crate::shared::state::AppState;
use crate::shared::utils::extract_cookie;

#[derive(Template, Debug)]
#[template(path = "account/sessions.html")]
pub struct SessionsTemplate {
    pub active: String,
    pub user_initial: String,
    pub user_name: String,
    pub sessions: Vec<SessionView>,
}

pub async fn sessions_get(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let user = common::get_account_user(&state, &headers).await?;
    let views = build_session_views(&state, user.id, &headers).await?;
    let tpl = SessionsTemplate {
        active: "sessions".into(),
        user_initial: user_initial(&user),
        user_name: user_display_name(&user),
        sessions: views,
    };
    Ok(common::render_tpl(&tpl)?.into_response())
}

#[derive(Debug, Deserialize)]
pub struct DeleteSessionForm {
    pub session_id: String,
}

pub async fn delete_session_post(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Form(form): axum::Form<DeleteSessionForm>,
) -> Result<Response, AppError> {
    let _user_id = common::get_account_user_id(&state, &headers).await?;
    let current = extract_cookie(&headers, ACCOUNT_TOKEN)
        .and_then(|t| t.split('.').next().map(String::from))
        .unwrap_or_default();
    if form.session_id == current {
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
    let current = extract_cookie(&headers, ACCOUNT_TOKEN)
        .and_then(|t| t.split('.').next().map(String::from))
        .unwrap_or_default();
    let all_ids = session::list_user_session_ids(&state.cache, user_id).await?;
    for sid in &all_ids {
        if sid != &current {
            let _ = session::revoke_session(&state.cache, sid).await;
        }
    }
    Ok(axum::Json(crate::api::response::MessageResponse::success(
        "All other sessions terminated.",
    ))
    .into_response())
}

async fn build_session_views(
    state: &AppState,
    user_id: uuid::Uuid,
    headers: &HeaderMap,
) -> Result<Vec<SessionView>, AppError> {
    let current = extract_cookie(headers, ACCOUNT_TOKEN)
        .and_then(|t| t.split('.').next().map(String::from))
        .unwrap_or_default();
    let session_ids = session::list_user_session_ids(&state.cache, user_id).await?;

    let mut views = Vec::new();
    for sid in &session_ids {
        if let Some(s) = session::get_session(&state.cache, sid).await.ok().flatten() {
            let short = if sid.len() > 12 {
                format!("{}...{}", &sid[..8], &sid[sid.len() - 4..])
            } else {
                sid.clone()
            };
            let is_current = sid == &current;
            views.push(SessionView {
                session_id: short,
                device: String::new(),
                location: String::new(),
                created_at: fmt_ts(s.created_at),
                current: is_current,
                expired: false,
            });
        }
    }
    Ok(views)
}

fn fmt_ts(ts: i64) -> String {
    chrono::DateTime::from_timestamp(ts, 0)
        .map(|dt| dt.format("%Y-%m-%d %H:%M").to_string())
        .unwrap_or_default()
}
