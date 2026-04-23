use crate::domain::oauth2::error;
use crate::domain::oauth2::models::TokenRequest;
use crate::domain::oauth2::service;
use crate::api::extractors::ValidatedForm;
use crate::shared::state::AppState;
use axum::extract::State;
use axum::response::{IntoResponse, Response};

#[utoipa::path(
    post,
    path = "/oauth2/token",
    tag = "OAuth2",
    request_body = crate::domain::oauth2::models::TokenRequest,
    responses(
        (status = 200, description = "Token response", body = crate::domain::oauth2::models::TokenResponse),
        (status = 400, description = "Invalid request"),
    )
)]
pub async fn token(
    State(state): State<AppState>,
    ValidatedForm(req): ValidatedForm<TokenRequest>,
) -> Response {
    match service::exchange_token(&state, &req).await {
        Ok(response) => axum::Json(response).into_response(),
        Err(e) => error::map_app_error(e),
    }
}
