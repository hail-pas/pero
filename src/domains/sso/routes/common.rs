use crate::domains::sso::session;
use crate::shared::error::AppError;
use crate::shared::state::AppState;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Redirect, Response};

pub async fn require_authenticated_sso_session(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<(String, crate::domains::sso::models::SsoSession), Response> {
    let (sid, sso) = session::require(&state.cache, headers)
        .await
        .map_err(|_| Redirect::to("/oauth2/authorize").into_response())?;
    if !sso.authenticated || sso.user_id.is_none() {
        return Err(Redirect::to("/sso/login").into_response());
    }
    Ok((sid, sso))
}

pub fn sso_error_redirect(message: &str) -> Result<Response, AppError> {
    Ok(Redirect::to(&format!(
        "/sso/login?error={}",
        urlencoding::encode(message)
    ))
    .into_response())
}
