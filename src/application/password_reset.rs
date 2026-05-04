use crate::domain::auth::repo::SessionStore;
use crate::domain::credential::repo::IdentityStore;
use crate::domain::oauth::repo::OAuth2TokenStore;
use crate::domain::user::repo::UserStore;
use crate::shared::constants::cache_keys::PASSWORD_RESET_PREFIX;
use crate::shared::error::AppError;
use crate::shared::kv::KvStore;

pub async fn request_reset(
    users: &dyn UserStore,
    kv: &dyn KvStore,
    identifier: &str,
    ttl_seconds: i64,
) -> Result<(), AppError> {
    if let Some(user) = find_user_for_reset(users, identifier).await? {
        let _token = crate::shared::utils::generate_token_and_cache(
            kv,
            PASSWORD_RESET_PREFIX,
            &user.id.to_string(),
            ttl_seconds,
        )
        .await?;
        tracing::info!(identifier = %identifier, "password reset token generated (email delivery stub)");
    }
    Ok(())
}

pub async fn complete_reset(
    users: &dyn UserStore,
    identities: &dyn IdentityStore,
    sessions: &dyn SessionStore,
    tokens: &dyn OAuth2TokenStore,
    kv: &dyn KvStore,
    token: &str,
    new_password: &str,
) -> Result<(), AppError> {
    let user_id = consume_reset_token(kv, token)
        .await
        .ok_or_else(|| AppError::BadRequest("Invalid or expired reset token.".into()))?;

    let user = users
        .find_by_id(user_id)
        .await?
        .ok_or_else(|| AppError::Unauthorized)?;
    if !user.is_active() {
        return Err(AppError::Unauthorized);
    }

    let hash = crate::shared::crypto::hash_secret(new_password)?;
    identities
        .update_credential(user_id, "password", &hash)
        .await?;
    sessions.revoke_all_for_user(user_id).await?;
    tokens.revoke_all_for_user(user_id).await?;
    Ok(())
}

pub async fn validate_reset_token(kv: &dyn KvStore, token: &str) -> Option<uuid::Uuid> {
    let uid_str: String =
        crate::shared::utils::validate_cached_token(kv, PASSWORD_RESET_PREFIX, token).await?;
    uid_str.parse().ok()
}

async fn consume_reset_token(kv: &dyn KvStore, token: &str) -> Option<uuid::Uuid> {
    let uid_str: String =
        crate::shared::utils::consume_cached_token(kv, PASSWORD_RESET_PREFIX, token).await?;
    uid_str.parse().ok()
}

async fn find_user_for_reset(
    users: &dyn UserStore,
    identifier: &str,
) -> Result<Option<crate::domain::user::entity::User>, AppError> {
    if identifier.contains('@') {
        users.find_by_email(identifier).await
    } else {
        users.find_by_phone(identifier).await
    }
}
