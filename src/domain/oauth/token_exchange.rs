use crate::domain::app::repo::AppStore;
use crate::domain::oauth::entity::AuthorizationCode;
use crate::domain::oauth::error::OAuth2Error;
use crate::domain::oauth::models::{GrantType, RevokeRequest, TokenRequest, TokenResponse};
use crate::domain::oauth::pkce;
use crate::domain::oauth::repo::{OAuth2ClientStore, OAuth2TokenStore, TokenSigner};
use crate::domain::oauth::service::{InvalidClientError, authenticate_client};
use crate::domain::oauth::token_builder::build_token_response;
use crate::domain::user::repo::UserStore;
use crate::shared::constants::oauth2::{GRANT_TYPE_AUTH_CODE, GRANT_TYPE_REFRESH_TOKEN};
use crate::shared::error::{AppError, require_found};

pub async fn exchange_token(
    clients: &dyn OAuth2ClientStore,
    tokens: &dyn OAuth2TokenStore,
    apps: &dyn AppStore,
    users: &dyn UserStore,
    signer: &dyn TokenSigner,
    access_ttl: i64,
    refresh_ttl: i64,
    oidc_issuer: &str,
    req: &TokenRequest,
) -> Result<TokenResponse, AppError> {
    match req.grant_type {
        GrantType::AuthorizationCode => {
            exchange_authorization_code(
                clients,
                tokens,
                apps,
                users,
                signer,
                access_ttl,
                refresh_ttl,
                oidc_issuer,
                req,
            )
            .await
        }
        GrantType::RefreshToken => {
            exchange_refresh_token(
                clients,
                tokens,
                apps,
                users,
                signer,
                access_ttl,
                refresh_ttl,
                oidc_issuer,
                req,
            )
            .await
        }
    }
}

pub async fn revoke_token(
    clients: &dyn OAuth2ClientStore,
    tokens: &dyn OAuth2TokenStore,
    apps: &dyn AppStore,
    req: &RevokeRequest,
) -> Result<(), AppError> {
    let client = authenticate_client(
        clients,
        apps,
        required_field(req.client_id.as_deref(), "client_id")?,
        required_field(req.client_secret.as_deref(), "client_secret")?,
        None,
        false,
        InvalidClientError::BadRequest,
    )
    .await?;

    crate::domain::oauth::service::ensure_app_enabled_pub(apps, &client).await?;
    tokens.revoke_token_if_owned(&req.token, client.id).await?;
    Ok(())
}

async fn exchange_authorization_code(
    clients: &dyn OAuth2ClientStore,
    tokens: &dyn OAuth2TokenStore,
    apps: &dyn AppStore,
    users: &dyn UserStore,
    signer: &dyn TokenSigner,
    access_ttl: i64,
    refresh_ttl: i64,
    oidc_issuer: &str,
    req: &TokenRequest,
) -> Result<TokenResponse, AppError> {
    let code = required_field(req.code.as_deref(), "code")?;
    let redirect_uri = required_field(req.redirect_uri.as_deref(), "redirect_uri")?;
    let client = authenticate_client(
        clients,
        apps,
        required_field(req.client_id.as_deref(), "client_id")?,
        required_field(req.client_secret.as_deref(), "client_secret")?,
        Some(GRANT_TYPE_AUTH_CODE),
        true,
        InvalidClientError::BadRequest,
    )
    .await?;
    let code_verifier = required_field(req.code_verifier.as_deref(), "code_verifier")?;

    let (auth_code, refresh_token) = tokens
        .exchange_auth_code(code, client.id, uuid::Uuid::nil(), &[], 0, refresh_ttl)
        .await?;

    validate_authorization_code(&auth_code, &client, redirect_uri, code_verifier)?;

    let user = load_active_user(users, auth_code.user_id).await?;

    build_token_response(
        signer,
        access_ttl,
        oidc_issuer,
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
    clients: &dyn OAuth2ClientStore,
    tokens: &dyn OAuth2TokenStore,
    apps: &dyn AppStore,
    users: &dyn UserStore,
    signer: &dyn TokenSigner,
    access_ttl: i64,
    refresh_ttl: i64,
    oidc_issuer: &str,
    req: &TokenRequest,
) -> Result<TokenResponse, AppError> {
    let old_refresh = required_field(req.refresh_token.as_deref(), "refresh_token")?;
    let client = authenticate_client(
        clients,
        apps,
        required_field(req.client_id.as_deref(), "client_id")?,
        required_field(req.client_secret.as_deref(), "client_secret")?,
        Some(GRANT_TYPE_REFRESH_TOKEN),
        true,
        InvalidClientError::BadRequest,
    )
    .await?;

    let stored = match tokens.find_active_refresh_for_update(old_refresh).await? {
        Some(token) => token,
        None => {
            return handle_refresh_replay_or_missing(tokens, old_refresh).await;
        }
    };

    if client.id != stored.client_id {
        return Err(OAuth2Error::ClientMismatch.into());
    }

    let (new_stored, new_refresh) = tokens
        .rotate_refresh_token(
            old_refresh,
            client.id,
            stored.user_id,
            &stored.scopes,
            stored.auth_time,
            refresh_ttl,
            stored.family_id,
        )
        .await?;

    let user = load_active_user(users, new_stored.user_id).await?;

    build_token_response(
        signer,
        access_ttl,
        oidc_issuer,
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
    client: &crate::domain::oauth::models::OAuth2Client,
    redirect_uri: &str,
    code_verifier: &str,
) -> Result<(), AppError> {
    if auth_code.client_id != client.id {
        return Err(OAuth2Error::ClientMismatch.into());
    }
    if auth_code.redirect_uri != redirect_uri {
        return Err(OAuth2Error::RedirectUriMismatch.into());
    }
    match (&auth_code.code_challenge, &auth_code.code_challenge_method) {
        (Some(challenge), Some(method)) => {
            if !pkce::verify_pkce(code_verifier, challenge, method) {
                return Err(OAuth2Error::PkceVerificationFailed.into());
            }
        }
        _ => {
            return Err(OAuth2Error::MissingPkceChallenge.into());
        }
    }
    Ok(())
}

async fn load_active_user(
    users: &dyn UserStore,
    user_id: uuid::Uuid,
) -> Result<crate::domain::user::models::User, AppError> {
    let user = require_found(users.find_by_id(user_id).await?, "user")?;
    if !user.is_active() {
        return Err(OAuth2Error::AccountDisabled.into());
    }
    Ok(user)
}

async fn handle_refresh_replay_or_missing(
    tokens: &dyn OAuth2TokenStore,
    refresh_token: &str,
) -> Result<TokenResponse, AppError> {
    if let Some(revoked) = tokens.find_revoked_by_token(refresh_token).await? {
        tracing::warn!(
            user_id = %revoked.user_id,
            client_id = %revoked.client_id,
            "refresh token replay detected, revoking token family"
        );
        if let Some(family_id) = revoked.family_id {
            tokens.revoke_token_family(family_id).await?;
        } else {
            tokens
                .revoke_all_for_user_client(revoked.user_id, revoked.client_id)
                .await?;
        }
        return Err(OAuth2Error::RefreshTokenReplay.into());
    }
    Err(OAuth2Error::InvalidRefreshToken.into())
}

fn required_field<'a>(value: Option<&'a str>, name: &str) -> Result<&'a str, AppError> {
    value.ok_or_else(move || OAuth2Error::MissingField(name.to_string()).into())
}
