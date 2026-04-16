use axum::Json;
use axum::extract::State;

use crate::domains::identity::repos::UserRepo;
use crate::domains::oauth2::models::{TokenRequest, TokenResponse};
use crate::domains::oauth2::pkce;
use crate::domains::oauth2::repos::{AuthCodeRepo, OAuth2ClientRepo, RefreshTokenRepo};
use crate::shared::error::AppError;
use crate::shared::jwt;
use crate::shared::state::AppState;

pub async fn token(
    State(state): State<AppState>,
    Json(req): Json<TokenRequest>,
) -> Result<Json<TokenResponse>, AppError> {
    match req.grant_type.as_str() {
        "authorization_code" => handle_authorization_code(&state, &req).await,
        "refresh_token" => handle_refresh_token(&state, &req).await,
        _ => Err(AppError::BadRequest("unsupported grant_type".into())),
    }
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
    let client_secret = req
        .client_secret
        .as_deref()
        .ok_or(AppError::BadRequest("missing client_secret".into()))?;
    let code_verifier = req
        .code_verifier
        .as_deref()
        .ok_or(AppError::BadRequest("missing code_verifier".into()))?;

    let client = OAuth2ClientRepo::find_by_client_id(&state.db, client_id_str)
        .await?
        .ok_or(AppError::BadRequest("invalid client_id".into()))?;

    let valid_secret = bcrypt::verify(client_secret, &client.client_secret_hash)
        .map_err(|e| AppError::Internal(format!("Secret verify error: {e}")))?;
    if !valid_secret {
        return Err(AppError::Unauthorized);
    }

    let ac = AuthCodeRepo::find_and_consume(&state.db, code)
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

    if let (Some(challenge), Some(method)) = (&ac.code_challenge, &ac.code_challenge_method) {
        if !pkce::verify_pkce(code_verifier, challenge, method) {
            return Err(AppError::BadRequest("PKCE verification failed".into()));
        }
    }

    let user = UserRepo::find_by_id(&state.db, ac.user_id)
        .await?
        .ok_or(AppError::NotFound("user".into()))?;

    let user_id_str = user.id.to_string();
    let roles = vec!["user".to_string()];

    let scope_str = Some(ac.scopes.join(" "));
    let access_token = jwt::sign_access_token(
        &user_id_str,
        roles,
        &state.jwt_keys,
        state.config.oauth2.access_token_ttl_minutes,
        scope_str,
    )?;

    let refresh_token_str = uuid::Uuid::new_v4().to_string().replace('-', "");
    RefreshTokenRepo::create(
        &state.db,
        client.id,
        user.id,
        &refresh_token_str,
        &ac.scopes,
        state.config.oauth2.refresh_token_ttl_days,
    )
    .await?;

    let id_token = build_id_token(&state, &user, &ac.scopes, None, &client.client_id)?;

    Ok(Json(TokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: state.config.oauth2.access_token_ttl_minutes * 60,
        refresh_token: Some(refresh_token_str),
        id_token: Some(id_token),
        scope: Some(ac.scopes.join(" ")),
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

    let stored = RefreshTokenRepo::find_by_token(&state.db, old_refresh)
        .await?
        .ok_or(AppError::BadRequest(
            "invalid or expired refresh token".into(),
        ))?;

    let client_id_str = req
        .client_id
        .as_deref()
        .ok_or(AppError::BadRequest("missing client_id".into()))?;
    let client = OAuth2ClientRepo::find_by_client_id(&state.db, client_id_str)
        .await?
        .ok_or(AppError::BadRequest("invalid client_id".into()))?;

    if client.id != stored.client_id {
        return Err(AppError::BadRequest("client mismatch".into()));
    }

    if let Some(secret) = req.client_secret.as_deref() {
        let valid = bcrypt::verify(secret, &client.client_secret_hash)
            .map_err(|e| AppError::Internal(format!("Secret verify error: {e}")))?;
        if !valid {
            return Err(AppError::Unauthorized);
        }
    }

    RefreshTokenRepo::revoke(&state.db, stored.id).await?;

    let user = UserRepo::find_by_id(&state.db, stored.user_id)
        .await?
        .ok_or(AppError::NotFound("user".into()))?;

    let user_id_str = user.id.to_string();
    let roles = vec!["user".to_string()];

    let scope_str = Some(stored.scopes.join(" "));
    let access_token = jwt::sign_access_token(
        &user_id_str,
        roles,
        &state.jwt_keys,
        state.config.oauth2.access_token_ttl_minutes,
        scope_str,
    )?;

    let new_refresh = uuid::Uuid::new_v4().to_string().replace('-', "");
    RefreshTokenRepo::create(
        &state.db,
        client.id,
        user.id,
        &new_refresh,
        &stored.scopes,
        state.config.oauth2.refresh_token_ttl_days,
    )
    .await?;

    let id_token = build_id_token(&state, &user, &stored.scopes, None, &client.client_id)?;

    Ok(Json(TokenResponse {
        access_token,
        token_type: "Bearer".to_string(),
        expires_in: state.config.oauth2.access_token_ttl_minutes * 60,
        refresh_token: Some(new_refresh),
        id_token: Some(id_token),
        scope: Some(stored.scopes.join(" ")),
    }))
}

fn build_id_token(
    state: &AppState,
    user: &crate::domains::identity::models::User,
    scopes: &[String],
    nonce: Option<String>,
    client_id: &str,
) -> Result<String, AppError> {
    use crate::shared::jwt::IdTokenClaims;
    use chrono::{TimeDelta, Utc};

    let now = Utc::now();
    let mut claims = IdTokenClaims {
        sub: user.id.to_string(),
        iss: state.config.oidc.issuer.clone(),
        aud: client_id.to_string(),
        exp: (now + TimeDelta::minutes(state.config.oauth2.access_token_ttl_minutes)).timestamp(),
        iat: now.timestamp(),
        auth_time: now.timestamp(),
        nonce,
        name: None,
        nickname: None,
        picture: None,
        email: None,
        email_verified: None,
        phone_number: None,
        phone_number_verified: None,
    };

    if scopes.contains(&"profile".to_string()) {
        claims.name = Some(user.username.clone());
        claims.nickname = user.nickname.clone();
        claims.picture = user.avatar_url.clone();
    }
    if scopes.contains(&"email".to_string()) {
        claims.email = Some(user.email.clone());
        claims.email_verified = Some(true);
    }
    if scopes.contains(&"phone".to_string()) {
        claims.phone_number = user.phone.clone();
        claims.phone_number_verified = Some(user.phone.is_some());
    }

    jwt::sign_id_token(&claims, &state.jwt_keys)
}
