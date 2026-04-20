use axum::Json;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use chrono::{TimeDelta, Utc};

use crate::domains::identity::repos::UserRepo;
use crate::domains::oauth2::error;
use crate::domains::oauth2::models::{GrantType, TokenRequest, TokenResponse};
use crate::domains::oauth2::pkce;
use crate::domains::oauth2::repos::{AuthCodeRepo, OAuth2ClientRepo, RefreshTokenRepo};
use crate::shared::constants::identity::DEFAULT_ROLE;
use crate::shared::constants::oauth2::scopes as oauth2_scopes;
use crate::shared::constants::oauth2::{
    GRANT_TYPE_AUTH_CODE, GRANT_TYPE_REFRESH_TOKEN, TOKEN_TYPE_BEARER,
};
use crate::shared::error::AppError;
use crate::shared::extractors::ValidatedJson;
use crate::shared::jwt::{self, IdTokenClaims};
use crate::shared::state::AppState;

#[utoipa::path(
    post,
    path = "/oauth2/token",
    tag = "OAuth2",
    request_body = crate::domains::oauth2::models::TokenRequest,
    responses(
        (status = 200, description = "Token response", body = crate::domains::oauth2::models::TokenResponse),
        (status = 400, description = "Invalid request"),
    )
)]
pub async fn token(
    State(state): State<AppState>,
    ValidatedJson(req): ValidatedJson<TokenRequest>,
) -> Response {
    let result = match req.grant_type {
        GrantType::AuthorizationCode => handle_authorization_code(&state, &req).await,
        GrantType::RefreshToken => handle_refresh_token(&state, &req).await,
    };
    match result {
        Ok(json) => json.into_response(),
        Err(e) => error::map_app_error(e),
    }
}

fn ensure_client_grant_allowed(
    client: &crate::domains::oauth2::models::OAuth2Client,
    grant_type: &str,
) -> Result<(), AppError> {
    if client.allows_grant_type(grant_type) {
        return Ok(());
    }
    Err(AppError::BadRequest(format!(
        "grant_type '{}' not allowed",
        grant_type
    )))
}

async fn handle_authorization_code(
    state: &AppState,
    req: &TokenRequest,
) -> Result<Json<TokenResponse>, AppError> {
    let code = req
        .code
        .as_deref()
        .ok_or(AppError::BadRequest("missing code".into()))?;
    let redirect_uri = req
        .redirect_uri
        .as_deref()
        .ok_or(AppError::BadRequest("missing redirect_uri".into()))?;
    let client_id_str = req
        .client_id
        .as_deref()
        .ok_or(AppError::BadRequest("missing client_id".into()))?;
    let code_verifier = req
        .code_verifier
        .as_deref()
        .ok_or(AppError::BadRequest("missing code_verifier".into()))?;

    let client = OAuth2ClientRepo::find_by_client_id(&state.db, client_id_str)
        .await?
        .ok_or(AppError::BadRequest("invalid client_id".into()))?;

    if !client.enabled {
        return Err(AppError::BadRequest("client is disabled".into()));
    }
    ensure_client_grant_allowed(&client, GRANT_TYPE_AUTH_CODE)?;

    let secret = req
        .client_secret
        .as_deref()
        .ok_or(AppError::BadRequest("missing client_secret".into()))?;
    if !client.verify_secret(secret)? {
        return Err(AppError::Unauthorized);
    }

    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let ac = AuthCodeRepo::find_and_consume(&mut *tx, code)
        .await?
        .ok_or(AppError::BadRequest(
            "invalid or expired authorization code".into(),
        ))?;

    if ac.client_id != client.id {
        return Err(AppError::BadRequest("client mismatch".into()));
    }
    if ac.redirect_uri != redirect_uri {
        return Err(AppError::BadRequest("redirect_uri mismatch".into()));
    }

    match (&ac.code_challenge, &ac.code_challenge_method) {
        (Some(challenge), Some(method)) => {
            if !pkce::verify_pkce(code_verifier, challenge, method) {
                return Err(AppError::BadRequest("PKCE verification failed".into()));
            }
        }
        _ => {
            return Err(AppError::BadRequest(
                "authorization code has no PKCE challenge".into(),
            ));
        }
    }

    let user = UserRepo::find_by_id(&mut *tx, ac.user_id)
        .await?
        .ok_or(AppError::NotFound("user".into()))?;

    if user.status != 1 {
        return Err(AppError::Forbidden("account is disabled".into()));
    }

    let user_id_str = user.id.to_string();
    let roles = vec![DEFAULT_ROLE.to_string()];

    let scope_str = ac.scopes.join(" ");
    let access_token = jwt::sign_access_token(
        &user_id_str,
        roles,
        &state.jwt_keys,
        state.config.oauth2.access_token_ttl_minutes,
        Some(scope_str.clone()),
    )?;

    let refresh_token_str = crate::shared::utils::random_hex_token();
    RefreshTokenRepo::create(
        &mut *tx,
        client.id,
        user.id,
        &refresh_token_str,
        &ac.scopes,
        ac.auth_time,
        state.config.oauth2.refresh_token_ttl_days,
    )
    .await?;

    tx.commit()
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let id_token = build_id_token(
        &state,
        &user,
        &ac.scopes,
        ac.nonce,
        &client.client_id,
        ac.auth_time,
    )?;

    Ok(Json(TokenResponse {
        access_token,
        token_type: TOKEN_TYPE_BEARER.to_string(),
        expires_in: state.config.oauth2.access_token_ttl_minutes * 60,
        refresh_token: Some(refresh_token_str),
        id_token: Some(id_token),
        scope: Some(scope_str),
    }))
}

async fn handle_refresh_token(
    state: &AppState,
    req: &TokenRequest,
) -> Result<Json<TokenResponse>, AppError> {
    let old_refresh = req
        .refresh_token
        .as_deref()
        .ok_or(AppError::BadRequest("missing refresh_token".into()))?;

    let client_id_str = req
        .client_id
        .as_deref()
        .ok_or(AppError::BadRequest("missing client_id".into()))?;
    let client = OAuth2ClientRepo::find_by_client_id(&state.db, client_id_str)
        .await?
        .ok_or(AppError::BadRequest("invalid client_id".into()))?;

    if !client.enabled {
        return Err(AppError::BadRequest("client is disabled".into()));
    }
    ensure_client_grant_allowed(&client, GRANT_TYPE_REFRESH_TOKEN)?;

    let secret = req
        .client_secret
        .as_deref()
        .ok_or(AppError::BadRequest("missing client_secret".into()))?;
    if !client.verify_secret(secret)? {
        return Err(AppError::Unauthorized);
    }

    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let stored = RefreshTokenRepo::find_and_revoke_by_token(&mut *tx, old_refresh).await?;

    let stored = match stored {
        Some(s) => s,
        None => {
            drop(tx);
            if let Some(revoked) =
                RefreshTokenRepo::find_revoked_by_token(&state.db, old_refresh).await?
            {
                tracing::warn!(
                    user_id = %revoked.user_id,
                    client_id = %revoked.client_id,
                    "refresh token replay detected, revoking all tokens for user-client pair"
                );
                RefreshTokenRepo::revoke_all_for_user_client(
                    &state.db,
                    revoked.user_id,
                    revoked.client_id,
                )
                .await?;
                return Err(AppError::Unauthorized);
            }
            return Err(AppError::BadRequest(
                "invalid or expired refresh token".into(),
            ));
        }
    };

    if client.id != stored.client_id {
        return Err(AppError::BadRequest("client mismatch".into()));
    }

    let user = UserRepo::find_by_id(&mut *tx, stored.user_id)
        .await?
        .ok_or(AppError::NotFound("user".into()))?;

    if user.status != 1 {
        return Err(AppError::Forbidden("account is disabled".into()));
    }

    let user_id_str = user.id.to_string();
    let roles = vec![DEFAULT_ROLE.to_string()];
    let scope_str = stored.scopes.join(" ");

    let access_token = jwt::sign_access_token(
        &user_id_str,
        roles,
        &state.jwt_keys,
        state.config.oauth2.access_token_ttl_minutes,
        Some(scope_str.clone()),
    )?;

    let new_refresh = crate::shared::utils::random_hex_token();
    RefreshTokenRepo::create(
        &mut *tx,
        client.id,
        user.id,
        &new_refresh,
        &stored.scopes,
        stored.auth_time,
        state.config.oauth2.refresh_token_ttl_days,
    )
    .await?;

    tx.commit()
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let id_token = build_id_token(
        &state,
        &user,
        &stored.scopes,
        None,
        &client.client_id,
        stored.auth_time,
    )?;

    Ok(Json(TokenResponse {
        access_token,
        token_type: TOKEN_TYPE_BEARER.to_string(),
        expires_in: state.config.oauth2.access_token_ttl_minutes * 60,
        refresh_token: Some(new_refresh),
        id_token: Some(id_token),
        scope: Some(scope_str),
    }))
}

fn has_scope(scopes: &[String], scope: &str) -> bool {
    scopes.iter().any(|s| s == scope)
}

fn apply_scope_claims(
    claims: &mut IdTokenClaims,
    user: &crate::domains::identity::models::User,
    scopes: &[String],
) {
    if has_scope(scopes, oauth2_scopes::PROFILE) {
        claims.name = Some(user.username.clone());
        claims.nickname = user.nickname.clone();
        claims.picture = user.avatar_url.clone();
    }
    if has_scope(scopes, oauth2_scopes::EMAIL) {
        claims.email = Some(user.email.clone());
        claims.email_verified = Some(user.email_verified);
    }
    if has_scope(scopes, oauth2_scopes::PHONE) {
        claims.phone_number = user.phone.clone();
        claims.phone_number_verified = Some(false);
    }
}

fn build_id_token(
    state: &AppState,
    user: &crate::domains::identity::models::User,
    scopes: &[String],
    nonce: Option<String>,
    client_id: &str,
    auth_time: i64,
) -> Result<String, AppError> {
    let now = Utc::now();
    let mut claims = IdTokenClaims {
        sub: user.id.to_string(),
        iss: state.config.oidc.issuer.clone(),
        aud: client_id.to_string(),
        exp: (now + TimeDelta::minutes(state.config.oauth2.access_token_ttl_minutes)).timestamp(),
        iat: now.timestamp(),
        auth_time,
        nonce,
        name: None,
        nickname: None,
        picture: None,
        email: None,
        email_verified: None,
        phone_number: None,
        phone_number_verified: None,
    };

    apply_scope_claims(&mut claims, user, scopes);

    jwt::sign_id_token(&claims, &state.jwt_keys)
}
