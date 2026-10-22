use axum::http::StatusCode;
use axum_extra::extract::cookie::CookieJar;

use crate::state::app::AppState;
use crate::state::session::SsoSession;

pub async fn extract_session(
    state: &AppState,
    jar: &CookieJar,
) -> Result<Option<SsoSession>, StatusCode> {
    let Some(cookie) = jar.get(&state.config.sso.session_cookie_name) else {
        return Ok(None);
    };
    state
        .session_service()
        .validate(cookie.value())
        .await
        .map_err(|error| {
            tracing::error!(%error, "Session validation unavailable");
            StatusCode::SERVICE_UNAVAILABLE
        })
}
