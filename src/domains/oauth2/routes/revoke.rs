use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

use crate::domains::oauth2::error;
use crate::domains::oauth2::models::RevokeRequest;
use crate::domains::oauth2::service;
use crate::shared::extractors::ValidatedForm;
use crate::shared::state::AppState;

#[utoipa::path(
    post,
    path = "/oauth2/revoke",
    tag = "OAuth2",
    request_body = crate::domains::oauth2::models::RevokeRequest,
    responses(
        (status = 200, description = "Token revoked"),
        (status = 400, description = "Invalid request"),
    )
)]
pub async fn revoke(
    State(state): State<AppState>,
    ValidatedForm(req): ValidatedForm<RevokeRequest>,
) -> Response {
    match service::revoke_token(&state, &req).await {
        Ok(()) => StatusCode::OK.into_response(),
        Err(e) => error::map_app_error(e),
    }
}
