use crate::api::extractors::{AuthUser, ValidatedJson};
use crate::api::response::{ApiResponse, MessageResponse};
use crate::domain::identity::authn::AuthService;
use crate::domain::identity::models::{
    LoginRequest, RefreshRequest, RefreshTokenResponse, TokenResponse,
};
use crate::domain::identity::session;
use crate::infra::jwt;
use crate::shared::constants::identity::DEFAULT_ROLE;
use crate::shared::error::AppError;
use crate::shared::state::AppState;
use axum::Json;
use axum::extract::State;
use axum::http::HeaderMap;
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
    headers: HeaderMap,
    ValidatedJson(req): ValidatedJson<LoginRequest>,
) -> Result<Json<ApiResponse<TokenResponse>>, AppError> {
    let user = AuthService::authenticate_with_password(
        &*state.repos.users,
        &*state.repos.identities,
        &req.identifier_type,
        &req.identifier,
        &req.password,
    )
    .await?;

    let (device, location) = crate::shared::utils::parse_user_agent(&headers);
    let token_response =
        crate::domain::identity::service::issue_tokens(
            &*state.repos.token_signer,
            &*state.repos.sessions,
            &user,
            state.config.jwt.access_ttl_minutes,
            state.config.jwt.refresh_ttl_days,
            &device,
            &location,
        ).await?;
    Ok(Json(ApiResponse::success(token_response)))
}

#[utoipa::path(
    post,
    path = "/auth/refresh",
    tag = "Identity",
    request_body = RefreshRequest,
    responses(
        (status = 200, description = "Token refreshed", body = ApiResponse<RefreshTokenResponse>),
        (status = 401, description = "Invalid refresh token"),
    )
)]
pub async fn refresh(
    State(state): State<AppState>,
    ValidatedJson(req): ValidatedJson<RefreshRequest>,
) -> Result<Json<ApiResponse<RefreshTokenResponse>>, AppError> {
    let session_id = session::parse_session_id(&req.refresh_token)?;
    let stored = state.repos.sessions.get(session_id)
        .await?
        .ok_or(AppError::Unauthorized)?;
    let refresh_hash = session::hash_refresh_token(&req.refresh_token);

    if stored.refresh_token_hash != refresh_hash {
        if stored.previous_refresh_token_hash.as_deref() == Some(refresh_hash.as_str()) {
            tracing::warn!(
                user_id = %stored.user_id,
                "refresh token replay detected, revoking session"
            );
            state.repos.sessions.revoke(session_id).await?;
            return Err(AppError::Unauthorized);
        }
        return Err(AppError::Unauthorized);
    }

    let user_id = stored.user_id;
    let user_id_str = user_id.to_string();

    let user = state.repos.users.find_by_id(user_id)
        .await?
        .ok_or(AppError::Unauthorized)?;

    if !user.is_active() {
        return Err(AppError::Forbidden("account is disabled".into()));
    }

    let roles = vec![DEFAULT_ROLE.to_string()];
    let access_token = jwt::sign_access_token(
        &user_id_str,
        roles,
        &state.jwt_keys,
        state.config.jwt.access_ttl_minutes,
        None,
        None,
        None,
        None,
    )?;

    let new_refresh_token = session::build_refresh_token(session_id);
    let rotated = state.repos.sessions.rotate(
        session_id,
        &refresh_hash,
        &new_refresh_token,
        state.config.jwt.refresh_ttl_days,
    )
    .await?;
    if !rotated {
        return Err(AppError::Unauthorized);
    }

    Ok(Json(ApiResponse::success(RefreshTokenResponse {
        access_token,
        refresh_token: new_refresh_token,
    })))
}

#[utoipa::path(
    post,
    path = "/auth/logout",
    tag = "Identity",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Logged out", body = MessageResponse),
        (status = 401, description = "Unauthorized"),
    )
)]
pub async fn logout(
    State(state): State<AppState>,
    auth_user: AuthUser,
) -> Result<Json<MessageResponse>, AppError> {
    state.repos.sessions.revoke_all_for_user(auth_user.user_id).await?;
    if let Err(e) = state.repos.oauth2_tokens.revoke_all_for_user(auth_user.user_id).await {
        tracing::warn!(error = %e, "failed to revoke oauth2 tokens after logout");
    }
    Ok(Json(MessageResponse::success("logged out")))
}
