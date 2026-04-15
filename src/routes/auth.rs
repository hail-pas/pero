use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};
use crate::cache::session;
use crate::db::repos::{UserRepo, UserDTO};
use crate::shared::error::AppError;
use crate::shared::response::ApiResponse;
use crate::shared::state::AppState;

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub user: UserDTO,
}

#[derive(Debug, Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

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

    let valid = bcrypt::verify(&req.password, &user.password_hash)
        .map_err(|e| AppError::Internal(format!("Password verify error: {e}")))?;
    if !valid {
        return Err(AppError::Unauthorized);
    }

    let user_id_str = user.id.to_string();
    let roles = vec!["user".to_string()];

    let access_token = crate::auth::jwt::sign_access_token(
        &user_id_str,
        roles.clone(),
        &state.config.jwt.secret,
        state.config.jwt.access_ttl_minutes,
    )?;

    let refresh_token = uuid::Uuid::new_v4().to_string();
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

pub async fn refresh(
    State(state): State<AppState>,
    Json(req): Json<RefreshRequest>,
) -> Result<Json<ApiResponse<serde_json::Value>>, AppError> {
    let parts: Vec<&str> = req.refresh_token.splitn(2, ':').collect();
    if parts.len() != 2 {
        return Err(AppError::Unauthorized);
    }
    let user_id_str = parts[0];
    let token = parts[1];

    let stored = session::get_refresh_token(&mut state.cache.clone(), user_id_str).await?;
    let stored = stored.ok_or(AppError::Unauthorized)?;

    if stored != token {
        return Err(AppError::Unauthorized);
    }

    let roles = vec!["user".to_string()];
    let access_token = crate::auth::jwt::sign_access_token(
        user_id_str,
        roles,
        &state.config.jwt.secret,
        state.config.jwt.access_ttl_minutes,
    )?;

    Ok(Json(ApiResponse::success(serde_json::json!({
        "access_token": access_token
    }))))
}

pub async fn logout(
    State(state): State<AppState>,
    axum::extract::Extension(claims): axum::extract::Extension<crate::auth::jwt::TokenClaims>,
) -> Result<Json<ApiResponse<()>>, AppError> {
    session::revoke_refresh_token(&mut state.cache.clone(), &claims.sub).await?;
    Ok(Json(ApiResponse::<()>::success_message("logged out")))
}
