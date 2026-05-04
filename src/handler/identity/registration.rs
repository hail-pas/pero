use crate::api::extractors::ValidatedJson;
use crate::api::response::ApiResponse;
use crate::application::identity::register as register_use_case;
use crate::domain::user::models::{CreateUserRequest, RegisterRequest, TokenResponse, UserDTO};
use crate::shared::error::AppError;
use crate::shared::state::AppState;
use axum::Json;
use axum::extract::State;
use axum::http::HeaderMap;
#[utoipa::path(
    post,
    path = "/api/identity/register",
    tag = "Identity",
    request_body = crate::api::schemas::user::RegisterRequest,
    responses(
        (status = 200, description = "User registered", body = crate::api::response::ApiResponse<crate::api::schemas::user::TokenResponse>),
        (status = 400, description = "Validation error"),
    )
)]
pub async fn register(
    State(state): State<AppState>,
    headers: HeaderMap,
    ValidatedJson(req): ValidatedJson<RegisterRequest>,
) -> Result<Json<ApiResponse<TokenResponse>>, AppError> {
    let (device, location) = crate::shared::utils::parse_user_agent(&headers);
    Ok(Json(ApiResponse::success(
        register_use_case::register_user(
            &*state.repos.users,
            &*state.repos.identities,
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
    request_body = crate::api::schemas::user::CreateUserRequest,
    responses(
        (status = 200, description = "User created", body = crate::api::response::ApiResponse<crate::api::schemas::user::UserDTO>),
        (status = 400, description = "Validation error"),
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_user(
    State(state): State<AppState>,
    ValidatedJson(req): ValidatedJson<CreateUserRequest>,
) -> Result<Json<ApiResponse<UserDTO>>, AppError> {
    Ok(Json(ApiResponse::success(
        register_use_case::create_user(&*state.repos.users, &*state.repos.identities, &req).await?,
    )))
}
