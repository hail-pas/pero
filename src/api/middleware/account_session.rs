use axum::extract::State;
use axum::http::HeaderMap;
use axum::http::header;
use axum::middleware::Next;
use axum::response::{IntoResponse, Redirect, Response};

use crate::handler::account::common;
use crate::shared::constants::cookies::ACCOUNT_TOKEN;
use crate::shared::state::AppState;

pub async fn account_session_gate(
    State(state): State<AppState>,
    request: axum::extract::Request,
    next: Next,
) -> Response {
    let headers = request.headers().clone();
    let path = request.uri().path().to_owned();

    match common::get_verified_account(&state, &headers).await {
        Ok((_user, _identity_session)) => {
            let mut response = next.run(request).await;
            if let Some(cookie) = maybe_refresh_cookie(&state, &headers) {
                response.headers_mut().append(header::SET_COOKIE, cookie);
            }
            response
        }
        Err(_) => {
            let next_url = urlencoding::encode(&path);
            Redirect::to(&format!("/account/login?next={}", next_url)).into_response()
        }
    }
}

fn maybe_refresh_cookie(state: &AppState, headers: &HeaderMap) -> Option<axum::http::HeaderValue> {
    let token = crate::shared::utils::extract_cookie(headers, ACCOUNT_TOKEN)?;
    let claims = crate::infra::jwt::decode_token_claims_unverified(&token).ok()?;

    let total_seconds: i64 = state.config.jwt.refresh_ttl_days * 86400;
    let remaining = claims.exp - chrono::Utc::now().timestamp();
    if remaining > total_seconds / 4 {
        return None;
    }

    let new_token = crate::infra::jwt::sign_access_token(
        &claims.sub,
        vec![crate::shared::constants::identity::DEFAULT_ROLE.into()],
        &state.jwt_keys,
        (total_seconds / 60).max(15),
        None,
        None,
        None,
        claims.sid.clone(),
    )
    .ok()?;

    crate::handler::sso::common::build_account_cookie_value(state, &new_token).ok()
}
