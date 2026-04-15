use axum::extract::State;
use axum::Json;
use crate::domains::identity::models::{RegisterRequest, CreateUserRequest, UserDTO, TokenResponse};
use crate::domains::identity::repos::{UserRepo, IdentityRepo};
use crate::shared::error::AppError;
use crate::shared::extractors::ValidatedJson;
use crate::shared::response::ApiResponse;
use crate::shared::state::AppState;

pub async fn register(
    State(state): State<AppState>,
    ValidatedJson(req): ValidatedJson<RegisterRequest>,
) -> Result<Json<ApiResponse<TokenResponse>>, AppError> {
    crate::domains::identity::helpers::validate_new_user(&state.db, &req.username, &req.email).await?;

    let password_hash = crate::domains::identity::helpers::hash_password(&req.password)?;

    let user = UserRepo::create(
        &state.db,
        &req.username,
        &req.email,
        None,
        None,
        Some(&password_hash),
    )
    .await?;

    IdentityRepo::create_password(&state.db, user.id, &password_hash).await?;

    let token_response = crate::domains::identity::helpers::issue_tokens(&state, &user).await?;
    Ok(Json(ApiResponse::success(token_response)))
}

pub async fn create_user(
    State(state): State<AppState>,
    ValidatedJson(req): ValidatedJson<CreateUserRequest>,
) -> Result<Json<ApiResponse<UserDTO>>, AppError> {
    crate::domains::identity::helpers::validate_new_user(&state.db, &req.username, &req.email).await?;

    let password_hash = crate::domains::identity::helpers::hash_password(&req.password)?;

    let user = UserRepo::create(
        &state.db,
        &req.username,
        &req.email,
        req.phone.as_deref(),
        req.nickname.as_deref(),
        Some(&password_hash),
    )
    .await?;

    IdentityRepo::create_password(&state.db, user.id, &password_hash).await?;

    Ok(Json(ApiResponse::success(user.into())))
}
