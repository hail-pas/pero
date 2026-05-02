use axum::http::HeaderMap;
use axum::http::header;
use axum::response::{IntoResponse, Redirect, Response};

use crate::config::SsoConfig;
use crate::domain::sso::models::SsoSession;
use crate::domain::sso::session;
use crate::shared::constants::cookies::{ACCOUNT_TOKEN, SSO_SESSION};
use crate::shared::constants::identity::DEFAULT_ROLE;
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
    build_cookie(SSO_SESSION, session_id, config, config.session_ttl_seconds)
}

pub fn clear_session_cookie(config: &SsoConfig) -> Result<axum::http::HeaderValue, AppError> {
    build_cookie(SSO_SESSION, "", config, 0)
}

pub async fn set_account_cookie(
    state: &AppState,
    user_id: uuid::Uuid,
    headers: &axum::http::HeaderMap,
) -> Result<axum::http::HeaderValue, AppError> {
    let (device, location) = crate::shared::utils::parse_user_agent(headers);
    let (identity_session, _refresh_token) = crate::domain::identity::session::create_session(
        &state.cache,
        user_id,
        state.config.jwt.refresh_ttl_days,
        &device,
        &location,
    )
    .await?;
    let ttl_seconds = state.config.jwt.refresh_ttl_days * 86400;
    let token = crate::infra::jwt::sign_access_token(
        &user_id.to_string(),
        vec![DEFAULT_ROLE.into()],
        &state.jwt_keys,
        (ttl_seconds / 60).max(15),
        None,
        None,
        None,
        Some(identity_session.session_id.clone()),
    )?;
    build_cookie(ACCOUNT_TOKEN, &token, &state.config.sso, ttl_seconds)
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

pub fn build_account_cookie_value(
    state: &AppState,
    token: &str,
) -> Result<axum::http::HeaderValue, AppError> {
    let ttl_seconds = state.config.jwt.refresh_ttl_days * 86400;
    build_cookie(ACCOUNT_TOKEN, token, &state.config.sso, ttl_seconds)
}

pub fn build_cookie(
    name: &str,
    value: &str,
    config: &SsoConfig,
    max_age: i64,
) -> Result<axum::http::HeaderValue, AppError> {
    let mut cookie = format!(
        "{}={}; Path=/; HttpOnly; SameSite={}; Max-Age={}",
        name, value, config.cookie_same_site, max_age
    );
    if config.cookie_secure {
        cookie.push_str("; Secure");
    }
    header::HeaderValue::from_str(&cookie)
        .map_err(|e| AppError::Internal(format!("invalid cookie header: {e}")))
}
