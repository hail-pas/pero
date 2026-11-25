use axum::extract::State;
use axum::response::{IntoResponse, Response};
use pero_api_axum::oauth::bearer_error_response;
use pero_error::protocol::oauth::BearerError;

use crate::{
    service::token_status::{self, ActiveAccess},
    state::app::AppState,
};

/// GET or POST /api/oauth2/userinfo
pub async fn userinfo(State(state): State<AppState>, headers: axum::http::HeaderMap) -> Response {
    let token = match super::extract_bearer(&headers) {
        Some(t) => t,
        None => return bearer_error_response(BearerError::invalid_token("Missing Bearer token")),
    };

    let ActiveAccess {
        claims,
        user,
        tenant,
        ..
    } = match token_status::active_access(&state, token).await {
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
    if let Some(context) = tenant {
        resp["tenant_id"] = serde_json::json!(context.tenant_id);
        resp["tenant_kind"] = serde_json::json!(context.tenant_kind);
        resp["membership_role"] = serde_json::json!(context.membership_role);
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
