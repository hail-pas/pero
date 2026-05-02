use crate::domain::identity::models::User;
use crate::domain::identity::store::UserRepo;
use crate::domain::oauth2::error_ext;
use crate::domain::oauth2::models::{
    AuthorizationCode, GrantType, RevokeRequest, TokenRequest, TokenResponse,
};
use crate::domain::oauth2::pkce;
use crate::domain::oauth2::service::{InvalidClientError, authenticate_client};
use crate::domain::oauth2::store::{AuthCodeRepo, RefreshTokenRepo};
use crate::domain::oauth2::token_builder::build_token_response;
use crate::shared::constants::oauth2::{GRANT_TYPE_AUTH_CODE, GRANT_TYPE_REFRESH_TOKEN};
use crate::shared::error::{AppError, require_found};
use crate::shared::state::AppState;

pub async fn exchange_token(
    state: &AppState,
    req: &TokenRequest,
) -> Result<TokenResponse, AppError> {
    match req.grant_type {
        GrantType::AuthorizationCode => exchange_authorization_code(state, req).await,
        GrantType::RefreshToken => exchange_refresh_token(state, req).await,
    }
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
        if token.client_id == client.id {
            RefreshTokenRepo::revoke(&mut *tx, token.id).await?;
        }
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

    let mut tx = state.db.begin().await?;

    let auth_code = AuthCodeRepo::find_active_for_update(&mut *tx, code)
        .await?
        .ok_or(error_ext::invalid_or_expired_auth_code())?;
    validate_authorization_code(&auth_code, &client, redirect_uri, code_verifier)?;

    if !AuthCodeRepo::consume(&mut *tx, &auth_code.code).await? {
        return Err(error_ext::invalid_or_expired_auth_code());
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

    tx.commit().await?;

    build_token_response(
        state,
        &client,
        &user,
        &auth_code.scopes,
        auth_code.auth_time,
        auth_code.nonce,
        auth_code.sid,
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

    let mut tx = state.db.begin().await?;

    let stored = match RefreshTokenRepo::find_active_for_update(&mut *tx, old_refresh).await? {
        Some(token) => token,
        None => {
            drop(tx);
            return handle_refresh_replay_or_missing(state, old_refresh).await;
        }
    };

    if client.id != stored.client_id {
        return Err(error_ext::client_mismatch());
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

    tx.commit().await?;

    build_token_response(
        state,
        &client,
        &user,
        &stored.scopes,
        stored.auth_time,
        None,
        None,
        new_refresh,
    )
}

fn validate_authorization_code(
    auth_code: &AuthorizationCode,
    client: &crate::domain::oauth2::models::OAuth2Client,
    redirect_uri: &str,
    code_verifier: &str,
) -> Result<(), AppError> {
    if auth_code.client_id != client.id {
        return Err(error_ext::client_mismatch());
    }
    if auth_code.redirect_uri != redirect_uri {
        return Err(error_ext::redirect_uri_mismatch());
    }
    match (&auth_code.code_challenge, &auth_code.code_challenge_method) {
        (Some(challenge), Some(method)) => {
            if !pkce::verify_pkce(code_verifier, challenge, method) {
                return Err(error_ext::pkce_verification_failed());
            }
        }
        _ => {
            return Err(error_ext::missing_pkce_challenge());
        }
    }
    Ok(())
}

async fn load_active_user<'a, E>(executor: E, user_id: uuid::Uuid) -> Result<User, AppError>
where
    E: sqlx::Executor<'a, Database = sqlx::Postgres>,
{
    let user = require_found(UserRepo::find_by_id(executor, user_id).await?, "user")?;
    if !user.is_active() {
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
    Err(error_ext::invalid_or_expired_refresh_token())
}

fn required_field<'a>(value: Option<&'a str>, name: &str) -> Result<&'a str, AppError> {
    value.ok_or_else(|| error_ext::missing_field(name))
}
