use crate::domains::identity::models::{LoginRequest, RefreshRequest, TokenResponse};
use crate::domains::identity::repos::{IdentityRepo, UserRepo};
use crate::domains::identity::session;
use crate::shared::constants::identity::{DEFAULT_ROLE, PROVIDER_PASSWORD};
use crate::shared::error::AppError;
use crate::shared::extractors::{AuthUser, ValidatedJson};
use crate::shared::jwt;
use crate::shared::response::ApiResponse;
use crate::shared::state::AppState;
use axum::Json;
use axum::extract::State;
use utoipa;

#[utoipa::path(
    post,
    path = "/api/identity/login",
    tag = "Identity",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "Login successful", body = ApiResponse<TokenResponse>),
        (status = 401, description = "Invalid credentials"),
    )
)]
pub async fn login(
    State(state): State<AppState>,
    ValidatedJson(req): ValidatedJson<LoginRequest>,
) -> Result<Json<ApiResponse<TokenResponse>>, AppError> {
    use crate::domains::identity::models::IdentifierType;

    let user = match req.identifier_type {
        IdentifierType::Email => UserRepo::find_by_email(&state.db, &req.identifier).await?,
        IdentifierType::Phone => UserRepo::find_by_phone(&state.db, &req.identifier).await?,
        IdentifierType::Username => UserRepo::find_by_username(&state.db, &req.identifier).await?,
    };

    let user = match user {
        Some(u) if u.status == 1 => u,
        Some(_) => return Err(AppError::Forbidden("account is disabled".into())),
        None => {
            let _ = bcrypt::verify(
                &req.password,
                "$2b$12$TrePSBin7KMS2YzgKJgNXeSKHaFjHOa/XYRm8kqDQoJHqWbsLCDKi",
            );
            return Err(AppError::Unauthorized);
        }
    };

    let identity = IdentityRepo::find_by_user_and_provider(&state.db, user.id, PROVIDER_PASSWORD)
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

#[utoipa::path(
    post,
    path = "/auth/refresh",
    tag = "Identity",
    request_body = RefreshRequest,
    responses(
        (status = 200, description = "Token refreshed"),
        (status = 401, description = "Invalid refresh token"),
    )
)]
pub async fn refresh(
    State(state): State<AppState>,
    ValidatedJson(req): ValidatedJson<RefreshRequest>,
) -> Result<Json<ApiResponse<serde_json::Value>>, AppError> {
    let session_id = session::parse_session_id(&req.refresh_token)?;
    let stored = session::get_session(&state.cache, session_id)
        .await?
        .ok_or(AppError::Unauthorized)?;
    let refresh_hash = session::hash_refresh_token(&req.refresh_token);

    if stored.refresh_token_hash != refresh_hash {
        if stored.previous_refresh_token_hash.as_deref() == Some(refresh_hash.as_str()) {
            tracing::warn!(
                user_id = %stored.user_id,
                "refresh token replay detected, revoking session"
            );
            session::revoke_session(&state.cache, session_id).await?;
            return Err(AppError::Unauthorized);
        }
        return Err(AppError::Unauthorized);
    }

    let user_id = stored.user_id;
    let user_id_str = user_id.to_string();

    let user = UserRepo::find_by_id(&state.db, user_id)
        .await?
        .ok_or(AppError::Unauthorized)?;

    if user.status != 1 {
        return Err(AppError::Forbidden("account is disabled".into()));
    }

    let roles = vec![DEFAULT_ROLE.to_string()];
    let access_token = jwt::sign_access_token(
        &user_id_str,
        roles,
        &state.jwt_keys,
        state.config.jwt.access_ttl_minutes,
        None,
    )?;

    let new_refresh_token = session::build_refresh_token(session_id);
    let rotated = session::rotate_refresh_token(
        &state.cache,
        session_id,
        &refresh_hash,
        &new_refresh_token,
        state.config.jwt.refresh_ttl_days,
    )
    .await?;
    if !rotated {
        return Err(AppError::Unauthorized);
    }

    Ok(Json(ApiResponse::success(serde_json::json!({
        "access_token": access_token,
        "refresh_token": new_refresh_token
    }))))
}

#[utoipa::path(
    post,
    path = "/auth/logout",
    tag = "Identity",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Logged out", body = serde_json::Value),
        (status = 401, description = "Unauthorized"),
    )
)]
pub async fn logout(
    State(state): State<AppState>,
    auth_user: AuthUser,
) -> Result<Json<ApiResponse<()>>, AppError> {
    session::revoke_user_sessions(&state.cache, auth_user.user_id).await?;
    Ok(Json(ApiResponse::<()>::success_message("logged out")))
}
