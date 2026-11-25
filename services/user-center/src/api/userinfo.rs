use axum::extract::State;
use axum::response::{IntoResponse, Response};
use pero_api_axum::oauth::bearer_error_response;
use pero_error::protocol::oauth::BearerError;

use crate::state::app::AppState;

/// GET or POST /api/oauth2/userinfo
pub async fn userinfo(State(state): State<AppState>, headers: axum::http::HeaderMap) -> Response {
    let token = match extract_bearer(&headers) {
        Some(t) => t,
        None => return bearer_error_response(BearerError::invalid_token("Missing Bearer token")),
    };

    let (claims, user, client) = match crate::service::token_status::active_access(&state, token)
        .await
    {
        Ok(Some(value)) => value,
        Ok(None) => return bearer_error_response(BearerError::invalid_token("Token is inactive")),
        Err(e) => return crate::web::util::dependency_error(e),
    };

    let scopes: Vec<String> = claims.scope.split_whitespace().map(String::from).collect();
    if !crate::service::scope::contains(&scopes, "openid") {
        return bearer_error_response(BearerError::insufficient_scope("openid"));
    }
    let mut resp = serde_json::to_value(crate::service::scope::user_claims(&user, &scopes))
        .expect("user claims contain only JSON primitives");
    resp["sub"] = serde_json::json!(user.id.to_string());
    if let Some(tenant_id) = claims.tenant_id.as_deref() {
        resp["tenant_id"] = serde_json::json!(tenant_id);
    }
    if let Some(id) = claims
        .tenant_id
        .as_deref()
        .and_then(|id| uuid::Uuid::parse_str(id).ok())
    {
        match crate::service::tenant_context::active(&state.db, user.id, client.app_id, id).await {
            Ok(Some(context)) => {
                resp["tenant_kind"] = serde_json::json!(context.tenant_kind);
                resp["membership_role"] = serde_json::json!(context.membership_role);
            }
            Ok(None) => {
                return bearer_error_response(BearerError::invalid_token("Tenant is inactive"));
            }
            Err(error) => return crate::web::util::dependency_error(error),
        }
    }
    if crate::service::scope::contains(&scopes, "profile") {
        resp["updated_at"] = serde_json::json!(user.updated_at.unix_timestamp());
    }

    (
        [
            (axum::http::header::CACHE_CONTROL, "no-store"),
            (axum::http::header::PRAGMA, "no-cache"),
        ],
        axum::Json(resp),
    )
        .into_response()
}

fn extract_bearer(headers: &axum::http::HeaderMap) -> Option<&str> {
    let (scheme, token) = headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .split_once(' ')?;
    let token = token.trim_start_matches(' ');
    (scheme.eq_ignore_ascii_case("Bearer") && !token.is_empty()).then_some(token)
}

#[cfg(test)]
mod tests {
    #[test]
    fn bearer_scheme_is_case_insensitive_and_requires_credentials() {
        for value in ["Bearer token", "bearer token", "bEaReR  token"] {
            let mut headers = axum::http::HeaderMap::new();
            headers.insert(axum::http::header::AUTHORIZATION, value.parse().unwrap());
            assert_eq!(super::extract_bearer(&headers), Some("token"));
        }
        for value in ["Basic token", "Bearer", "Bearer   "] {
            let mut headers = axum::http::HeaderMap::new();
            headers.insert(axum::http::header::AUTHORIZATION, value.parse().unwrap());
            assert_eq!(super::extract_bearer(&headers), None);
        }
    }
}
