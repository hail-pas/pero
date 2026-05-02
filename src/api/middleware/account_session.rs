use axum::extract::State;
use axum::http::header;
use axum::middleware::Next;
use axum::response::{IntoResponse, Redirect, Response};

use crate::shared::constants::cookies::ACCOUNT_TOKEN;
use crate::shared::state::AppState;
use crate::shared::utils::extract_cookie;

pub async fn account_session_gate(
    State(state): State<AppState>,
    request: axum::extract::Request,
    next: Next,
) -> Response {
    let headers = request.headers().clone();
    let path = request.uri().path().to_owned();

    match check_account_cookie(&state, &headers).await {
        Some(cookie) => {
            let mut response = next.run(request).await;
            if let Some(cookie) = cookie {
                response.headers_mut().append(header::SET_COOKIE, cookie);
            }
            response
        }
        None => {
            let next_url = urlencoding::encode(&path);
            Redirect::to(&format!("/account/login?next={}", next_url)).into_response()
        }
    }
}

async fn check_account_cookie(
    state: &AppState,
    headers: &axum::http::HeaderMap,
) -> Option<Option<axum::http::HeaderValue>> {
    let token = extract_cookie(headers, ACCOUNT_TOKEN)?;
    let claims = crate::infra::jwt::verify_token(&token, &state.jwt_keys).ok()?;

    if let Some(ref sid) = claims.sid {
        let exists = crate::domain::identity::session::get_session(&state.cache, sid)
            .await
            .unwrap_or(None)
            .is_some();
        if !exists {
            return None;
        }
    }

    let total_seconds: i64 = state.config.jwt.refresh_ttl_days * 86400;
    let remaining = claims.exp - chrono::Utc::now().timestamp();
    if remaining > total_seconds / 4 {
        return Some(None);
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

    let cookie = crate::handler::sso::common::build_account_cookie_value(state, &new_token).ok()?;
    Some(Some(cookie))
}
