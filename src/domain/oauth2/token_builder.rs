use chrono::{TimeDelta, Utc};

use crate::domain::identity::models::User;
use crate::domain::oauth2::models::{OAuth2Client, TokenResponse};
use crate::domain::oidc::claims::ScopedClaims;
use crate::shared::constants::identity::DEFAULT_ROLE;
use crate::shared::constants::oauth2::TOKEN_TYPE_BEARER;
use crate::shared::error::AppError;
use crate::infra::jwt::{self, IdTokenClaims};
use crate::shared::state::AppState;

pub fn build_token_response(
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

fn build_id_token(
    state: &AppState,
    user: &User,
    scopes: &[String],
    nonce: Option<String>,
    client_id: &str,
    auth_time: i64,
) -> Result<String, AppError> {
    let now = Utc::now();
    let claims = ScopedClaims::from_user_and_scopes(user, scopes);
    let id_claims = IdTokenClaims {
        sub: user.id.to_string(),
        iss: state.config.oidc.issuer.clone(),
        aud: client_id.to_string(),
        exp: (now + TimeDelta::minutes(state.config.oauth2.access_token_ttl_minutes)).timestamp(),
        iat: now.timestamp(),
        auth_time,
        nonce,
        name: claims.name,
        nickname: claims.nickname,
        picture: claims.picture,
        email: claims.email,
        email_verified: claims.email_verified,
        phone_number: claims.phone_number,
        phone_number_verified: claims.phone_number_verified,
    };
    jwt::sign_id_token(&id_claims, &state.jwt_keys)
}
