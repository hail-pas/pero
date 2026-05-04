use crate::domain::app::repo::AppStore;
use crate::domain::oauth::models::{RevokeRequest, TokenRequest, TokenResponse};
use crate::domain::oauth::repo::{OAuth2ClientStore, RefreshTokenStore, TokenFamilyStore, TokenSigner};
use crate::domain::user::repo::UserStore;
use crate::shared::error::AppError;

pub async fn exchange_token(
    clients: &dyn OAuth2ClientStore,
    refresh_tokens: &dyn RefreshTokenStore,
    token_families: &dyn TokenFamilyStore,
    apps: &dyn AppStore,
    users: &dyn UserStore,
    signer: &dyn TokenSigner,
    access_ttl: i64,
    refresh_ttl: i64,
    oidc_issuer: &str,
    req: &TokenRequest,
) -> Result<TokenResponse, AppError> {
    crate::domain::oauth::token_exchange::exchange_token(
        clients,
        refresh_tokens,
        token_families,
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

pub async fn exchange_authorization_code(
    clients: &dyn OAuth2ClientStore,
    refresh_tokens: &dyn RefreshTokenStore,
    token_families: &dyn TokenFamilyStore,
    apps: &dyn AppStore,
    users: &dyn UserStore,
    signer: &dyn TokenSigner,
    access_ttl: i64,
    refresh_ttl: i64,
    oidc_issuer: &str,
    req: &TokenRequest,
) -> Result<TokenResponse, AppError> {
    exchange_token(
        clients,
        refresh_tokens,
        token_families,
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

pub async fn rotate_refresh_token(
    clients: &dyn OAuth2ClientStore,
    refresh_tokens: &dyn RefreshTokenStore,
    token_families: &dyn TokenFamilyStore,
    apps: &dyn AppStore,
    users: &dyn UserStore,
    signer: &dyn TokenSigner,
    access_ttl: i64,
    refresh_ttl: i64,
    oidc_issuer: &str,
    req: &TokenRequest,
) -> Result<TokenResponse, AppError> {
    exchange_token(
        clients,
        refresh_tokens,
        token_families,
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

pub async fn revoke_token(
    clients: &dyn OAuth2ClientStore,
    refresh_tokens: &dyn RefreshTokenStore,
    apps: &dyn AppStore,
    req: &RevokeRequest,
) -> Result<(), AppError> {
    crate::domain::oauth::token_exchange::revoke_token(clients, refresh_tokens, apps, req).await
}
