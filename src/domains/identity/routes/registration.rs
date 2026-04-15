use axum::extract::State;
use axum::Json;
use crate::domains::identity::models::{RegisterRequest, CreateUserRequest, UserDTO, TokenResponse};
use crate::domains::identity::repos::{UserRepo, IdentityRepo};
use crate::shared::error::AppError;
use crate::shared::extractors::ValidatedJson;
use crate::shared::response::ApiResponse;
use crate::shared::state::AppState;
use crate::shared::jwt;
use crate::cache::session;

pub async fn register(
    State(state): State<AppState>,
    ValidatedJson(req): ValidatedJson<RegisterRequest>,
) -> Result<Json<ApiResponse<TokenResponse>>, AppError> {
    if UserRepo::find_by_username(&state.db, &req.username).await?.is_some() {
        return Err(AppError::Conflict(format!("username '{}' already exists", req.username)));
    }
    if UserRepo::find_by_email(&state.db, &req.email).await?.is_some() {
        return Err(AppError::Conflict(format!("email '{}' already exists", req.email)));
    }

    let password_hash = bcrypt::hash(&req.password, bcrypt::DEFAULT_COST)
        .map_err(|e| AppError::Internal(format!("Password hash error: {e}")))?;

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

    let user_id_str = user.id.to_string();
    let roles = vec!["user".to_string()];
    let access_token = jwt::sign_access_token(
        &user_id_str,
        roles,
        &state.jwt_keys,
        state.config.jwt.access_ttl_minutes,
    )?;

    let refresh_token = format!("{}:{}", user.id, uuid::Uuid::new_v4());
    session::store_refresh_token(
        &mut state.cache.clone(),
        &user_id_str,
        &refresh_token,
        state.config.jwt.refresh_ttl_days,
    )
    .await?;

    Ok(Json(ApiResponse::success(TokenResponse {
        access_token,
        refresh_token,
        user: user.into(),
    })))
}

pub async fn create_user(
    State(state): State<AppState>,
    ValidatedJson(req): ValidatedJson<CreateUserRequest>,
) -> Result<Json<ApiResponse<UserDTO>>, AppError> {
    if UserRepo::find_by_username(&state.db, &req.username).await?.is_some() {
        return Err(AppError::Conflict(format!("username '{}' already exists", req.username)));
    }
    if UserRepo::find_by_email(&state.db, &req.email).await?.is_some() {
        return Err(AppError::Conflict(format!("email '{}' already exists", req.email)));
    }

    let password_hash = bcrypt::hash(&req.password, bcrypt::DEFAULT_COST)
        .map_err(|e| AppError::Internal(format!("Password hash error: {e}")))?;

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
