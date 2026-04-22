use base64::Engine;
use chrono::{TimeDelta, Utc};

use crate::domains::identity::models::User;
use crate::domains::identity::repos::UserRepo;
use crate::domains::oauth2::models::{
    AuthorizationCode, CreateClientRequest, GrantType, OAuth2Client, OAuth2ClientDTO,
    RevokeRequest, TokenRequest, TokenResponse, UpdateClientRequest,
};
use crate::domains::oauth2::pkce;
use crate::domains::oauth2::repos::{AuthCodeRepo, OAuth2ClientRepo, RefreshTokenRepo};
use crate::shared::constants::identity::DEFAULT_ROLE;
use crate::shared::constants::oauth2::scopes as oauth2_scopes;
use crate::shared::constants::oauth2::{
    GRANT_TYPE_AUTH_CODE, GRANT_TYPE_REFRESH_TOKEN, TOKEN_TYPE_BEARER,
};
use crate::shared::error::AppError;
use crate::shared::jwt::{self, IdTokenClaims};
use crate::shared::response::PageData;
use crate::shared::state::AppState;

pub enum InvalidClientError {
    BadRequest,
    Unauthorized,
}

pub struct CreatedClient {
    pub client: OAuth2Client,
    pub client_secret: String,
}

pub async fn exchange_token(
    state: &AppState,
    req: &TokenRequest,
) -> Result<TokenResponse, AppError> {
    match req.grant_type {
        GrantType::AuthorizationCode => exchange_authorization_code(state, req).await,
        GrantType::RefreshToken => exchange_refresh_token(state, req).await,
    }
}

pub async fn create_client(
    state: &AppState,
    req: &CreateClientRequest,
) -> Result<CreatedClient, AppError> {
    let client_id = crate::shared::utils::random_hex_token();
    let client_secret = crate::shared::utils::random_hex_token();
    let client_secret_hash = crate::domains::identity::helpers::hash_password(&client_secret)?;
    let client = OAuth2ClientRepo::create(&state.db, &client_id, &client_secret_hash, req).await?;
    Ok(CreatedClient {
        client,
        client_secret,
    })
}

pub async fn list_clients(
    state: &AppState,
    page: i64,
    page_size: i64,
) -> Result<PageData<OAuth2ClientDTO>, AppError> {
    let (clients, total) = OAuth2ClientRepo::list(&state.db, page, page_size).await?;
    let items = clients.into_iter().map(OAuth2ClientDTO::from).collect();
    Ok(PageData::new(items, total, page, page_size))
}

pub async fn get_client(state: &AppState, id: uuid::Uuid) -> Result<OAuth2ClientDTO, AppError> {
    Ok(OAuth2ClientRepo::find_by_id_or_err(&state.db, id)
        .await?
        .into())
}

pub async fn update_client(
    state: &AppState,
    id: uuid::Uuid,
    req: &UpdateClientRequest,
) -> Result<OAuth2ClientDTO, AppError> {
    Ok(OAuth2ClientRepo::update(&state.db, id, req).await?.into())
}

pub async fn delete_client(state: &AppState, id: uuid::Uuid) -> Result<(), AppError> {
    OAuth2ClientRepo::delete(&state.db, id).await
}

pub async fn revoke_token(state: &AppState, req: &RevokeRequest) -> Result<(), AppError> {
    let client = authenticate_client(
        state,
        required_field(req.client_id.as_deref(), "client_id")?,
        required_field(req.client_secret.as_deref(), "client_secret")?,
        None,
        false,
        InvalidClientError::BadRequest,
    )
    .await?;

    let mut tx = state.db.begin().await?;
    if let Some(token) = RefreshTokenRepo::find_active_for_update(&mut *tx, &req.token).await? {
        if token.client_id != client.id {
            return Err(AppError::Unauthorized);
        }
        RefreshTokenRepo::revoke(&mut *tx, token.id).await?;
    }
    tx.commit().await?;
    Ok(())
}

async fn exchange_authorization_code(
    state: &AppState,
    req: &TokenRequest,
) -> Result<TokenResponse, AppError> {
    let code = required_field(req.code.as_deref(), "code")?;
    let redirect_uri = required_field(req.redirect_uri.as_deref(), "redirect_uri")?;
    let client = authenticate_client(
        state,
        required_field(req.client_id.as_deref(), "client_id")?,
        required_field(req.client_secret.as_deref(), "client_secret")?,
        Some(GRANT_TYPE_AUTH_CODE),
        true,
        InvalidClientError::BadRequest,
    )
    .await?;
    let code_verifier = required_field(req.code_verifier.as_deref(), "code_verifier")?;

    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let auth_code = AuthCodeRepo::find_active_for_update(&mut *tx, code)
        .await?
        .ok_or(AppError::BadRequest(
            "invalid or expired authorization code".into(),
        ))?;
    validate_authorization_code(&auth_code, &client, redirect_uri, code_verifier)?;

    if !AuthCodeRepo::consume(&mut *tx, &auth_code.code).await? {
        return Err(AppError::BadRequest(
            "invalid or expired authorization code".into(),
        ));
    }

    let user = load_active_user(&mut *tx, auth_code.user_id).await?;
    let refresh_token = crate::shared::utils::random_hex_token();
    RefreshTokenRepo::create(
        &mut *tx,
        client.id,
        user.id,
        &refresh_token,
        &auth_code.scopes,
        auth_code.auth_time,
        state.config.oauth2.refresh_token_ttl_days,
    )
    .await?;

    tx.commit()
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    build_token_response(
        state,
        &client,
        &user,
        &auth_code.scopes,
        auth_code.auth_time,
        auth_code.nonce,
        refresh_token,
    )
}

async fn exchange_refresh_token(
    state: &AppState,
    req: &TokenRequest,
) -> Result<TokenResponse, AppError> {
    let old_refresh = required_field(req.refresh_token.as_deref(), "refresh_token")?;
    let client = authenticate_client(
        state,
        required_field(req.client_id.as_deref(), "client_id")?,
        required_field(req.client_secret.as_deref(), "client_secret")?,
        Some(GRANT_TYPE_REFRESH_TOKEN),
        true,
        InvalidClientError::BadRequest,
    )
    .await?;

    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let stored = match RefreshTokenRepo::find_active_for_update(&mut *tx, old_refresh).await? {
        Some(token) => token,
        None => {
            drop(tx);
            return handle_refresh_replay_or_missing(state, old_refresh).await;
        }
    };

    if client.id != stored.client_id {
        return Err(AppError::BadRequest("client mismatch".into()));
    }

    RefreshTokenRepo::revoke(&mut *tx, stored.id).await?;
    let user = load_active_user(&mut *tx, stored.user_id).await?;

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

    build_token_response(
        state,
        &client,
        &user,
        &stored.scopes,
        stored.auth_time,
        None,
        new_refresh,
    )
}

pub async fn authenticate_client(
    state: &AppState,
    client_id: &str,
    client_secret: &str,
    grant_type: Option<&str>,
    require_enabled: bool,
    invalid_client_error: InvalidClientError,
) -> Result<OAuth2Client, AppError> {
    let client = match OAuth2ClientRepo::find_by_client_id(&state.db, client_id).await? {
        Some(client) => client,
        None => {
            fake_secret_probe(client_secret);
            return Err(match invalid_client_error {
                InvalidClientError::BadRequest => AppError::BadRequest("invalid client_id".into()),
                InvalidClientError::Unauthorized => AppError::Unauthorized,
            });
        }
    };

    if require_enabled && !client.enabled {
        return Err(match invalid_client_error {
            InvalidClientError::BadRequest => AppError::BadRequest("client is disabled".into()),
            InvalidClientError::Unauthorized => AppError::Forbidden("client is disabled".into()),
        });
    }
    if let Some(grant_type) = grant_type {
        ensure_client_grant_allowed(&client, grant_type)?;
    }
    if !client.verify_secret(client_secret)? {
        return Err(AppError::Unauthorized);
    }
    Ok(client)
}

pub fn parse_basic_client_auth_header(auth_header: &str) -> Result<(String, String), AppError> {
    let encoded = auth_header
        .strip_prefix("Basic ")
        .or_else(|| auth_header.strip_prefix("basic "))
        .ok_or_else(|| AppError::BadRequest("Expected Basic auth".into()))?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| AppError::Unauthorized)?;
    let decoded_str = String::from_utf8(decoded).map_err(|_| AppError::Unauthorized)?;
    let mut parts = decoded_str.splitn(2, ':');
    let client_id = parts.next().unwrap_or("");
    let client_secret = parts.next().unwrap_or("");
    if client_id.is_empty() || client_secret.is_empty() {
        return Err(AppError::Unauthorized);
    }
    Ok((client_id.to_string(), client_secret.to_string()))
}

fn ensure_client_grant_allowed(client: &OAuth2Client, grant_type: &str) -> Result<(), AppError> {
    if client.allows_grant_type(grant_type) {
        return Ok(());
    }
    Err(AppError::BadRequest(format!(
        "grant_type '{}' not allowed",
        grant_type
    )))
}

fn validate_authorization_code(
    auth_code: &AuthorizationCode,
    client: &OAuth2Client,
    redirect_uri: &str,
    code_verifier: &str,
) -> Result<(), AppError> {
    if auth_code.client_id != client.id {
        return Err(AppError::BadRequest("client mismatch".into()));
    }
    if auth_code.redirect_uri != redirect_uri {
        return Err(AppError::BadRequest("redirect_uri mismatch".into()));
    }
    match (&auth_code.code_challenge, &auth_code.code_challenge_method) {
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
    Ok(())
}

async fn load_active_user<'a, E>(executor: E, user_id: uuid::Uuid) -> Result<User, AppError>
where
    E: sqlx::Executor<'a, Database = sqlx::Postgres>,
{
    let user = UserRepo::find_by_id(executor, user_id)
        .await?
        .ok_or(AppError::NotFound("user".into()))?;
    if user.status != 1 {
        return Err(AppError::Forbidden("account is disabled".into()));
    }
    Ok(user)
}

async fn handle_refresh_replay_or_missing(
    state: &AppState,
    refresh_token: &str,
) -> Result<TokenResponse, AppError> {
    if let Some(revoked) = RefreshTokenRepo::find_revoked_by_token(&state.db, refresh_token).await?
    {
        tracing::warn!(
            user_id = %revoked.user_id,
            client_id = %revoked.client_id,
            "refresh token replay detected, revoking all tokens for user-client pair"
        );
        RefreshTokenRepo::revoke_all_for_user_client(&state.db, revoked.user_id, revoked.client_id)
            .await?;
        return Err(AppError::Unauthorized);
    }
    Err(AppError::BadRequest(
        "invalid or expired refresh token".into(),
    ))
}

fn build_token_response(
    state: &AppState,
    client: &OAuth2Client,
    user: &User,
    scopes: &[String],
    auth_time: i64,
    nonce: Option<String>,
    refresh_token: String,
) -> Result<TokenResponse, AppError> {
    let user_id_str = user.id.to_string();
    let scope = scopes.join(" ");
    let access_token = jwt::sign_access_token(
        &user_id_str,
        vec![DEFAULT_ROLE.to_string()],
        &state.jwt_keys,
        state.config.oauth2.access_token_ttl_minutes,
        Some(scope.clone()),
        Some(client.client_id.clone()),
        Some(client.app_id.to_string()),
    )?;
    let id_token = build_id_token(state, user, scopes, nonce, &client.client_id, auth_time)?;

    Ok(TokenResponse {
        access_token,
        token_type: TOKEN_TYPE_BEARER.to_string(),
        expires_in: state.config.oauth2.access_token_ttl_minutes * 60,
        refresh_token: Some(refresh_token),
        id_token: Some(id_token),
        scope: Some(scope),
    })
}

fn has_scope(scopes: &[String], scope: &str) -> bool {
    scopes.iter().any(|s| s == scope)
}

fn apply_scope_claims(claims: &mut IdTokenClaims, user: &User, scopes: &[String]) {
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
    user: &User,
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

fn required_field<'a>(value: Option<&'a str>, name: &str) -> Result<&'a str, AppError> {
    value.ok_or_else(|| AppError::BadRequest(format!("missing {name}")))
}

fn fake_secret_probe(client_secret: &str) {
    let _ = bcrypt::verify(
        client_secret,
        "$2b$12$TrePSBin7KMS2YzgKJgNXeSKHaFjHOa/XYRm8kqDQoJHqWbsLCDKi",
    );
}
