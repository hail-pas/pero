use crate::api::extractors::ValidatedForm;
use crate::domain::oauth2::error;
use crate::domain::oauth2::models::TokenRequest;
use crate::domain::oauth2::service;
use crate::shared::state::AppState;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};

#[utoipa::path(
    post,
    path = "/oauth2/token",
    tag = "OAuth2",
    request_body(
        content = crate::domain::oauth2::models::TokenRequest,
        content_type = "application/x-www-form-urlencoded",
    ),
    responses(
        (status = 200, description = "Token response", body = crate::domain::oauth2::models::TokenResponse),
        (status = 400, description = "Invalid request"),
    )
)]
pub async fn token(
    State(state): State<AppState>,
    headers: HeaderMap,
    ValidatedForm(req): ValidatedForm<TokenRequest>,
) -> Response {
    let req = match service::resolve_client_credentials(&headers, req) {
        Ok(req) => req,
        Err(e) => return error::map_app_error(e),
    };
    match service::exchange_token(&state, &req).await {
        Ok(response) => axum::Json(response).into_response(),
        Err(e) => error::map_app_error(e),
    }
}
