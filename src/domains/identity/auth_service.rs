use crate::domains::identity::helpers;
use crate::domains::identity::models::{IdentifierType, User};
use crate::domains::identity::repos::{IdentityRepo, UserRepo};
use crate::domains::identity::session;
use crate::shared::constants::identity::PROVIDER_PASSWORD;
use crate::shared::error::AppError;
use crate::shared::state::AppState;
use uuid::Uuid;

pub struct AuthService;

impl AuthService {
    fn constant_time_password_probe(password: &str) {
        let _ = bcrypt::verify(
            password,
            "$2b$12$TrePSBin7KMS2YzgKJgNXeSKHaFjHOa/XYRm8kqDQoJHqWbsLCDKi",
        );
    }

    async fn find_user_by_identifier(
        state: &AppState,
        identifier_type: &IdentifierType,
        identifier: &str,
    ) -> Result<Option<User>, AppError> {
        match identifier_type {
            IdentifierType::Email => UserRepo::find_by_email(&state.db, identifier).await,
            IdentifierType::Phone => UserRepo::find_by_phone(&state.db, identifier).await,
            IdentifierType::Username => UserRepo::find_by_username(&state.db, identifier).await,
        }
    }

    async fn load_password_credential(state: &AppState, user_id: Uuid) -> Result<String, AppError> {
        let identity =
            IdentityRepo::find_by_user_and_provider(&state.db, user_id, PROVIDER_PASSWORD)
                .await?
                .ok_or(AppError::Unauthorized)?;

        identity.credential.ok_or(AppError::Unauthorized)
    }

    pub async fn register_user_with_password(
        state: &AppState,
        username: &str,
        email: &str,
        phone: Option<&str>,
        nickname: Option<&str>,
        password: &str,
    ) -> Result<User, AppError> {
        let mut tx = state.db.begin().await?;
        let user =
            helpers::create_user_with_password(&mut tx, username, email, phone, nickname, password)
                .await?;
        tx.commit().await?;
        Ok(user)
    }

    pub async fn authenticate_with_password(
        state: &AppState,
        identifier_type: &IdentifierType,
        identifier: &str,
        password: &str,
    ) -> Result<User, AppError> {
        let user = Self::find_user_by_identifier(state, identifier_type, identifier).await?;
        let user = match user {
            Some(user) if user.status == 1 => user,
            Some(_) => return Err(AppError::Forbidden("account is disabled".into())),
            None => {
                Self::constant_time_password_probe(password);
                return Err(AppError::Unauthorized);
            }
        };

        let credential = match Self::load_password_credential(state, user.id).await {
            Ok(credential) => credential,
            Err(AppError::Unauthorized) => {
                Self::constant_time_password_probe(password);
                return Err(AppError::Unauthorized);
            }
            Err(err) => return Err(err),
        };

        let valid = bcrypt::verify(password, &credential)
            .map_err(|e| AppError::Internal(format!("Password verify error: {e}")))?;
        if !valid {
            return Err(AppError::Unauthorized);
        }

        Ok(user)
    }

    pub async fn change_password(
        state: &AppState,
        user_id: Uuid,
        old_password: &str,
        new_password: &str,
    ) -> Result<(), AppError> {
        if old_password == new_password {
            return Err(AppError::BadRequest(
                "new password must differ from old password".into(),
            ));
        }

        let credential = Self::load_password_credential(state, user_id).await?;
        let valid = bcrypt::verify(old_password, &credential)
            .map_err(|e| AppError::Internal(format!("Password verify error: {e}")))?;
        if !valid {
            return Err(AppError::BadRequest("old password is incorrect".into()));
        }

        let new_hash = helpers::hash_password(new_password)?;
        let mut tx = state.db.begin().await?;
        IdentityRepo::update_credential(&mut *tx, user_id, PROVIDER_PASSWORD, &new_hash).await?;
        tx.commit().await?;

        if let Err(e) = session::revoke_user_sessions(&state.cache, user_id).await {
            tracing::warn!(error = %e, "failed to revoke refresh token after password change");
        }

        Ok(())
    }
}
