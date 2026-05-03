use chrono::{TimeDelta, Utc};

use crate::domain::identity::models::User;
use crate::domain::oauth2::models::{OAuth2Client, TokenResponse};
use crate::domain::oauth2::repo::{AccessTokenParams, TokenSigner};
use crate::domain::oidc::claims::ScopedClaims;
use crate::shared::constants::identity::DEFAULT_ROLE;
use crate::shared::constants::oauth2::TOKEN_TYPE_BEARER;
use crate::shared::error::AppError;

pub fn build_token_response(
    signer: &dyn TokenSigner,
    access_ttl_minutes: i64,
    oidc_issuer: &str,
    client: &OAuth2Client,
    user: &User,
    scopes: &[String],
    auth_time: i64,
    nonce: Option<String>,
    sid: Option<String>,
    refresh_token: Option<String>,
) -> Result<TokenResponse, AppError> {
    let user_id_str = user.id.to_string();
    let scope = scopes.join(" ");
    let access_token = signer.sign_access_token(
        AccessTokenParams {
            sub: user_id_str,
            roles: vec![DEFAULT_ROLE.to_string()],
            scope: Some(scope.clone()),
            azp: Some(client.client_id.clone()),
            app_id: Some(client.app_id.to_string()),
            sid: None,
            ttl_minutes: access_ttl_minutes,
        },
    )?;
    let has_openid = scopes
        .iter()
        .any(|s| s == crate::shared::constants::oauth2::scopes::OPENID);
    let id_token = if has_openid {
        Some(build_id_token(
            signer,
            access_ttl_minutes,
            oidc_issuer,
            user,
            scopes,
            nonce,
            &client.client_id,
            auth_time,
            sid.clone(),
        )?)
    } else {
        None
    };

    Ok(TokenResponse {
        access_token,
        token_type: TOKEN_TYPE_BEARER.to_string(),
        expires_in: access_ttl_minutes * 60,
        refresh_token,
        id_token,
        scope: Some(scope),
    })
}

fn build_id_token(
    signer: &dyn TokenSigner,
    access_ttl_minutes: i64,
    oidc_issuer: &str,
    user: &User,
    scopes: &[String],
    nonce: Option<String>,
    client_id: &str,
    auth_time: i64,
    sid: Option<String>,
) -> Result<String, AppError> {
    let now = Utc::now();
    let claims = ScopedClaims::from_user_and_scopes(user, scopes);
    signer.sign_id_token(
        user.id.to_string(),
        oidc_issuer.to_string(),
        client_id.to_string(),
        (now + TimeDelta::minutes(access_ttl_minutes)).timestamp(),
        now.timestamp(),
        auth_time,
        nonce,
        claims.name,
        claims.nickname,
        claims.picture,
        claims.email,
        claims.email_verified,
        claims.phone_number,
        claims.phone_number_verified,
        sid,
    )
}
