use crate::api::extractors::ValidatedJson;
use crate::api::response::ApiResponse;
use crate::domain::identity::models::{CreateUserRequest, RegisterRequest, TokenResponse, UserDTO};
use crate::domain::identity::service;
use crate::shared::error::AppError;
use crate::shared::state::AppState;
use axum::Json;
use axum::extract::State;
use axum::http::HeaderMap;
use utoipa;

#[utoipa::path(
    post,
    path = "/api/identity/register",
    tag = "Identity",
    request_body = RegisterRequest,
    responses(
        (status = 200, description = "Registration successful", body = ApiResponse<TokenResponse>),
        (status = 400, description = "Bad request"),
        (status = 409, description = "Username or email already exists"),
    )
)]
pub async fn register(
    State(state): State<AppState>,
    headers: HeaderMap,
    ValidatedJson(req): ValidatedJson<RegisterRequest>,
) -> Result<Json<ApiResponse<TokenResponse>>, AppError> {
    Ok(Json(ApiResponse::success(
        service::register_user(&state, &req, &headers).await?,
    )))
}

#[utoipa::path(
    post,
    path = "/api/users",
    tag = "Identity",
    security(("bearer_auth" = [])),
    request_body = CreateUserRequest,
    responses(
        (status = 200, description = "User created", body = ApiResponse<UserDTO>),
        (status = 401, description = "Unauthorized"),
        (status = 409, description = "Username or email already exists"),
    )
)]
pub async fn create_user(
    State(state): State<AppState>,
    ValidatedJson(req): ValidatedJson<CreateUserRequest>,
) -> Result<Json<ApiResponse<UserDTO>>, AppError> {
    Ok(Json(ApiResponse::success(
        service::create_user(&state, &req).await?,
    )))
}
