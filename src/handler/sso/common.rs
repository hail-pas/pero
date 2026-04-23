use askama::Template;
use axum::http::HeaderMap;
use axum::http::header;
use axum::response::{Html, IntoResponse, Redirect, Response};

use crate::config::SsoConfig;
use crate::domain::sso::models::SsoSession;
use crate::domain::sso::session::{self, COOKIE_NAME};
use crate::shared::error::AppError;
use crate::shared::state::AppState;

pub type SessionResult = Result<(String, SsoSession), Response>;

pub async fn load_sso_session(
    state: &AppState,
    headers: &HeaderMap,
) -> SessionResult {
    session::require(&state.cache, headers)
        .await
        .map_err(|_| Redirect::to("/oauth2/authorize").into_response())
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

pub fn render_tpl<T: Template>(tpl: &T) -> Result<Html<String>, AppError> {
    tpl.render()
        .map(Html)
        .map_err(|e| AppError::Internal(e.to_string()))
}

pub fn set_session_cookie(config: &SsoConfig, session_id: &str) -> axum::http::HeaderValue {
    build_cookie_header(config, session_id, config.session_ttl_seconds)
}

pub fn clear_session_cookie(config: &SsoConfig) -> axum::http::HeaderValue {
    build_cookie_header(config, "", 0)
}

pub fn sso_error_redirect(message: &str) -> Result<Response, AppError> {
    Ok(Redirect::to(&format!(
        "/sso/login?error={}",
        urlencoding::encode(message)
    ))
    .into_response())
}

fn build_cookie_header(
    config: &SsoConfig,
    session_id: &str,
    max_age: i64,
) -> axum::http::HeaderValue {
    let mut cookie = format!(
        "{}={}; Path=/; HttpOnly; SameSite={}; Max-Age={}",
        COOKIE_NAME, session_id, config.cookie_same_site, max_age
    );
    if config.cookie_secure {
        cookie.push_str("; Secure");
    }
    header::HeaderValue::from_str(&cookie).expect("invalid SSO cookie header")
}
