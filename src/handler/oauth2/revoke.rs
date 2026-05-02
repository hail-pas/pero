use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};

use crate::api::extractors::ValidatedForm;
use crate::domain::oauth2::error;
use crate::domain::oauth2::models::RevokeRequest;
use crate::domain::oauth2::service;
use crate::shared::state::AppState;

#[utoipa::path(
    post,
    path = "/oauth2/revoke",
    tag = "OAuth2",
    request_body(
        content = crate::domain::oauth2::models::RevokeRequest,
        content_type = "application/x-www-form-urlencoded",
    ),
    responses(
        (status = 200, description = "Token revoked"),
        (status = 400, description = "Invalid request"),
    )
)]
pub async fn revoke(
    State(state): State<AppState>,
    headers: HeaderMap,
    ValidatedForm(req): ValidatedForm<RevokeRequest>,
) -> Response {
    let req = match service::resolve_client_credentials(&headers, req) {
        Ok(req) => req,
        Err(e) => return error::map_app_error(e),
    };
    match service::revoke_token(&state, &req).await {
        Ok(()) => StatusCode::OK.into_response(),
        Err(e) => error::map_app_error(e),
    }
}
