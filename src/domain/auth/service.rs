use crate::domain::auth::repo::SessionStore;
use crate::domain::credential::repo::IdentityStore;
use crate::domain::oauth::repo::RefreshTokenStore;
use crate::domain::user::error;
use crate::domain::user::models::{IdentifierType, User};
use crate::domain::user::repo::UserStore;
use crate::shared::constants::identity::PROVIDER_PASSWORD;
use crate::shared::error::AppError;
use uuid::Uuid;

pub use crate::domain::user::service::{delete_user, issue_tokens};

pub struct AuthService;

impl AuthService {
    fn constant_time_password_probe(password: &str) {
        let _ = crate::shared::crypto::verify_secret(
            password,
            crate::shared::constants::security::FAKE_BCRYPT_HASH,
        );
    }

    async fn find_user_by_identifier(
        users: &dyn UserStore,
        identifier_type: &IdentifierType,
        identifier: &str,
    ) -> Result<Option<User>, AppError> {
        match identifier_type {
            IdentifierType::Email => users.find_by_email(identifier).await,
            IdentifierType::Phone => users.find_by_phone(identifier).await,
            IdentifierType::Username => users.find_by_username(identifier).await,
        }
    }

    async fn load_password_credential(
        identities: &dyn IdentityStore,
        user_id: Uuid,
    ) -> Result<String, AppError> {
        let identity = identities
            .find_by_user_and_provider(user_id, PROVIDER_PASSWORD)
            .await?
            .ok_or(AppError::Unauthorized)?;

        identity.credential.ok_or(AppError::Unauthorized)
    }

    pub async fn register_user_with_password(
        users: &dyn UserStore,
        identities: &dyn IdentityStore,
        username: &str,
        email: Option<&str>,
        phone: Option<&str>,
        nickname: Option<&str>,
        password: &str,
    ) -> Result<User, AppError> {
        let password_hash = crate::domain::credential::service::hash_password(password)?;
        users
            .check_new_user_conflicts(username, email, phone)
            .await?;
        let user = users
            .create_with_password(username, email, phone, nickname, &password_hash)
            .await?;
        identities.create_password(user.id, &password_hash).await?;
        Ok(user)
    }

    pub async fn authenticate_with_password(
        users: &dyn UserStore,
        identities: &dyn IdentityStore,
        identifier_type: &IdentifierType,
        identifier: &str,
        password: &str,
    ) -> Result<User, AppError> {
        let user = Self::find_user_by_identifier(users, identifier_type, identifier).await?;
        let user = match user {
            Some(user) if user.is_active() => user,
            Some(_) => {
                Self::constant_time_password_probe(password);
                return Err(AppError::Unauthorized);
            }
            None => {
                Self::constant_time_password_probe(password);
                return Err(AppError::Unauthorized);
            }
        };

        match identifier_type {
            IdentifierType::Email if !user.email_verified => {
                Self::constant_time_password_probe(password);
                return Err(AppError::Unauthorized);
            }
            IdentifierType::Phone if !user.phone_verified => {
                Self::constant_time_password_probe(password);
                return Err(AppError::Unauthorized);
            }
            _ => {}
        }

        let credential = match Self::load_password_credential(identities, user.id).await {
            Ok(credential) => credential,
            Err(AppError::Unauthorized) => {
                Self::constant_time_password_probe(password);
                return Err(AppError::Unauthorized);
            }
            Err(err) => return Err(err),
        };

        let valid = crate::shared::crypto::verify_secret(password, &credential)?;
        if !valid {
            return Err(AppError::Unauthorized);
        }

        Ok(user)
    }

    pub async fn change_password(
        _users: &dyn UserStore,
        identities: &dyn IdentityStore,
        sessions_store: &dyn SessionStore,
        token_store: &dyn RefreshTokenStore,
        user_id: Uuid,
        old_password: &str,
        new_password: &str,
    ) -> Result<(), AppError> {
        if old_password == new_password {
            return Err(error::password_must_differ());
        }

        let credential = Self::load_password_credential(identities, user_id).await?;
        let valid = crate::shared::crypto::verify_secret(old_password, &credential)?;
        if !valid {
            return Err(error::old_password_incorrect());
        }

        let new_hash = crate::domain::credential::service::hash_password(new_password)?;
        identities
            .update_credential(user_id, PROVIDER_PASSWORD, &new_hash)
            .await?;

        if let Err(e) = sessions_store.revoke_all_for_user(user_id).await {
            tracing::warn!(error = %e, "failed to revoke refresh token after password change");
        }
        if let Err(e) = token_store.revoke_all_for_user(user_id).await {
            tracing::warn!(error = %e, "failed to revoke oauth2 tokens after password change");
        }

        Ok(())
    }
}
