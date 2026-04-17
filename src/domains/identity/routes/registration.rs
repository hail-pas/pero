use crate::domains::identity::models::{
    CreateUserRequest, RegisterRequest, TokenResponse, UserDTO,
};
use crate::domains::identity::repos::{IdentityRepo, UserRepo};
use crate::shared::error::AppError;
use crate::shared::extractors::ValidatedJson;
use crate::shared::response::ApiResponse;
use crate::shared::state::AppState;
use axum::Json;
use axum::extract::State;
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
    ValidatedJson(req): ValidatedJson<RegisterRequest>,
) -> Result<Json<ApiResponse<TokenResponse>>, AppError> {
    crate::domains::identity::helpers::validate_new_user(&state.db, &req.username, &req.email)
        .await?;

    let password_hash = crate::domains::identity::helpers::hash_password(&req.password)?;

    let mut tx = state.db.begin().await.map_err(|e| AppError::Internal(e.to_string()))?;
    let user = UserRepo::create(
        &mut *tx,
        &req.username,
        &req.email,
        req.phone.as_deref(),
        req.nickname.as_deref(),
        Some(&password_hash),
    )
    .await?;

    IdentityRepo::create_password(&mut *tx, user.id, &password_hash).await?;
    tx.commit().await.map_err(|e| AppError::Internal(e.to_string()))?;

    let token_response = crate::domains::identity::helpers::issue_tokens(&state, &user).await?;
    Ok(Json(ApiResponse::success(token_response)))
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
    crate::domains::identity::helpers::validate_new_user(&state.db, &req.username, &req.email)
        .await?;

    let password_hash = crate::domains::identity::helpers::hash_password(&req.password)?;

    let mut tx = state.db.begin().await.map_err(|e| AppError::Internal(e.to_string()))?;
    let user = UserRepo::create(
        &mut *tx,
        &req.username,
        &req.email,
        req.phone.as_deref(),
        req.nickname.as_deref(),
        Some(&password_hash),
    )
    .await?;

    IdentityRepo::create_password(&mut *tx, user.id, &password_hash).await?;
    tx.commit().await.map_err(|e| AppError::Internal(e.to_string()))?;

    Ok(Json(ApiResponse::success(user.into())))
}
