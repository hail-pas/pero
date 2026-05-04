use crate::api::extractors::ValidatedJson;
use crate::api::response::ApiResponse;
use crate::domain::credential::service;
use crate::domain::user::models::{CreateUserRequest, RegisterRequest, TokenResponse, UserDTO};
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
    let (device, location) = crate::shared::utils::parse_user_agent(&headers);
    Ok(Json(ApiResponse::success(
        service::register_user(
            &*state.repos.users,
            &*state.repos.sessions,
            &*state.repos.token_signer,
            &req,
            &device,
            &location,
            state.config.jwt.access_ttl_minutes,
            state.config.jwt.refresh_ttl_days,
        )
        .await?,
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
        service::create_user(&*state.repos.users, &req).await?,
    )))
}
