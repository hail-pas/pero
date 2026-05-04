use crate::domain::auth::repo::SessionStore;
use crate::domain::oauth::repo::{AccessTokenParams, TokenSigner};
use crate::domain::user::models::{TokenResponse, User};
use crate::shared::constants::identity::DEFAULT_ROLE;
use crate::shared::error::AppError;

pub async fn issue_tokens(
    signer: &dyn TokenSigner,
    sessions_store: &dyn SessionStore,
    user: &User,
    access_ttl_minutes: i64,
    refresh_ttl_days: i64,
    device: &str,
    location: &str,
) -> Result<TokenResponse, AppError> {
    let access_token = signer.sign_access_token(AccessTokenParams {
        sub: user.id.to_string(),
        roles: vec![DEFAULT_ROLE.to_string()],
        scope: None,
        azp: None,
        app_id: None,
        sid: None,
        ttl_minutes: access_ttl_minutes,
    })?;

    let (_identity_session, refresh_token) = sessions_store
        .create(user.id, refresh_ttl_days, device, location)
        .await?;

    Ok(TokenResponse {
        access_token,
        refresh_token,
        user: user.clone().into(),
    })
}
