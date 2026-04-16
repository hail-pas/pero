use crate::cache::session;
use crate::domains::identity::models::{LoginRequest, RefreshRequest, TokenResponse};
use crate::domains::identity::repos::{IdentityRepo, UserRepo};
use crate::shared::error::AppError;
use crate::shared::extractors::AuthUser;
use crate::shared::jwt;
use crate::shared::response::ApiResponse;
use crate::shared::state::AppState;
use axum::Json;
use axum::extract::State;

pub async fn login(
    State(state): State<AppState>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<ApiResponse<TokenResponse>>, AppError> {
    let user = UserRepo::find_by_username(&state.db, &req.username)
        .await?
        .ok_or(AppError::Unauthorized)?;

    if user.status != 1 {
        return Err(AppError::Forbidden("account is disabled".into()));
    }

    let identity = IdentityRepo::find_by_user_and_provider(&state.db, user.id, "password")
        .await?
        .ok_or(AppError::Unauthorized)?;

    let credential = identity
        .credential
        .as_deref()
        .ok_or(AppError::Unauthorized)?;

    let valid = bcrypt::verify(&req.password, credential)
        .map_err(|e| AppError::Internal(format!("Password verify error: {e}")))?;
    if !valid {
        return Err(AppError::Unauthorized);
    }

    let token_response = crate::domains::identity::helpers::issue_tokens(&state, &user).await?;
    Ok(Json(ApiResponse::success(token_response)))
}

pub async fn refresh(
    State(state): State<AppState>,
    Json(req): Json<RefreshRequest>,
) -> Result<Json<ApiResponse<serde_json::Value>>, AppError> {
    let parts: Vec<&str> = req.refresh_token.splitn(2, ':').collect();
    if parts.len() != 2 {
        return Err(AppError::Unauthorized);
    }
    let user_id_str = parts[0];

    let stored = session::get_refresh_token(&mut state.cache.clone(), user_id_str).await?;
    let stored = stored.ok_or(AppError::Unauthorized)?;

    if stored != req.refresh_token {
        return Err(AppError::Unauthorized);
    }

    let user_id: uuid::Uuid = user_id_str.parse().map_err(|_| AppError::Unauthorized)?;

    let user = UserRepo::find_by_id(&state.db, user_id)
        .await?
        .ok_or(AppError::Unauthorized)?;

    if user.status != 1 {
        return Err(AppError::Forbidden("account is disabled".into()));
    }

    let roles = vec!["user".to_string()];
    let access_token = jwt::sign_access_token(
        user_id_str,
        roles,
        &state.jwt_keys,
        state.config.jwt.access_ttl_minutes,
        None,
    )?;

    let new_refresh_token = format!("{}:{}", user.id, uuid::Uuid::new_v4());
    session::store_refresh_token(
        &mut state.cache.clone(),
        user_id_str,
        &new_refresh_token,
        state.config.jwt.refresh_ttl_days,
    )
    .await?;

    Ok(Json(ApiResponse::success(serde_json::json!({
        "access_token": access_token,
        "refresh_token": new_refresh_token
    }))))
}

pub async fn logout(
    State(state): State<AppState>,
    auth_user: AuthUser,
) -> Result<Json<ApiResponse<()>>, AppError> {
    session::revoke_refresh_token(&mut state.cache.clone(), &auth_user.user_id.to_string()).await?;
    Ok(Json(ApiResponse::<()>::success_message("logged out")))
}
