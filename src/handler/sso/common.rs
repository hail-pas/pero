use axum::http::HeaderMap;
use axum::http::header;
use axum::response::{IntoResponse, Redirect, Response};

use crate::config::SsoConfig;
use crate::domain::sso::models::SsoSession;
use crate::domain::sso::session;
use crate::shared::constants::cookies::SSO_SESSION;
use crate::shared::error::AppError;
use crate::shared::state::AppState;

pub use crate::shared::utils::render_tpl;

pub type SessionResult = Result<(String, SsoSession), Response>;

pub async fn load_sso_session(state: &AppState, headers: &HeaderMap) -> SessionResult {
    session::require(&state.cache, headers)
        .await
        .map_err(|e| match e {
            AppError::BadRequest(_) | AppError::NotFound(_) | AppError::Unauthorized => {
                Redirect::to("/oauth2/authorize").into_response()
            }
            other => other.into_response(),
        })
}

pub async fn require_authenticated_sso_session(
    state: &AppState,
    headers: &HeaderMap,
) -> SessionResult {
    let (sid, sso) = load_sso_session(state, headers).await?;
    if !sso.authenticated || sso.user_id.is_none() {
        return Err(Redirect::to("/sso/login").into_response());
    }
    Ok((sid, sso))
}

pub fn set_session_cookie(
    config: &SsoConfig,
    session_id: &str,
) -> Result<axum::http::HeaderValue, AppError> {
    build_cookie_header(config, session_id, config.session_ttl_seconds)
}

pub fn clear_session_cookie(config: &SsoConfig) -> Result<axum::http::HeaderValue, AppError> {
    build_cookie_header(config, "", 0)
}

pub async fn mark_sso_authenticated(
    state: &AppState,
    session_id: &str,
    sso: &mut SsoSession,
    user_id: uuid::Uuid,
) -> Result<(), AppError> {
    sso.user_id = Some(user_id);
    sso.authenticated = true;
    sso.auth_time = Some(chrono::Utc::now().timestamp());
    session::update(
        &state.cache,
        session_id,
        sso,
        state.config.sso.session_ttl_seconds,
    )
    .await
}

fn build_cookie_header(
    config: &SsoConfig,
    session_id: &str,
    max_age: i64,
) -> Result<axum::http::HeaderValue, AppError> {
    let mut cookie = format!(
        "{}={}; Path=/; HttpOnly; SameSite={}; Max-Age={}",
        SSO_SESSION, session_id, config.cookie_same_site, max_age
    );
    if config.cookie_secure {
        cookie.push_str("; Secure");
    }
    header::HeaderValue::from_str(&cookie)
        .map_err(|e| AppError::Internal(format!("invalid SSO cookie header: {e}")))
}
