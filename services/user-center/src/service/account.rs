use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QuerySelect, TransactionTrait};
use uuid::Uuid;

use crate::db::entity::users;
use crate::db::enums::{IdentityKind, UserStatus};
use crate::service::password::PasswordIdentityService;
use crate::state::app::AppState;

pub enum PasswordResetError {
    MissingToken,
    InvalidToken,
    TokenAlreadyUsed,
    PasswordMismatch,
    InvalidPassword(String),
    Internal,
}

impl PasswordResetError {
    pub fn message_key(&self) -> &str {
        match self {
            Self::MissingToken => "missing_token",
            Self::InvalidToken => "invalid_token",
            Self::TokenAlreadyUsed => "token_already_used",
            Self::PasswordMismatch => "password_mismatch",
            Self::InvalidPassword(msg) => msg.as_str(),
            Self::Internal => "internal_error",
        }
    }
}

pub struct AccountService<'a> {
    state: &'a AppState,
}

impl<'a> AccountService<'a> {
    pub fn new(state: &'a AppState) -> Self {
        Self { state }
    }

    pub async fn change_password(
        &self,
        session: &crate::state::session::SsoSession,
        old_password: Option<&str>,
        new_password: &str,
        confirm_password: &str,
    ) -> Result<(), super::ManagementError> {
        use super::ManagementError;
        use crate::db::entity::{identities, sso_sessions};
        use pero_cache_redis::{
            RateLimitError, enforce_rate_limit, rate_limit_key::rl_change_password,
        };

        let key = rl_change_password.key(&session.user_id.to_string())?;
        match enforce_rate_limit(&self.state.cache, &key, 5).await {
            Ok(()) => {}
            Err(RateLimitError::Denied { .. }) => {
                return Err(ManagementError::Invalid("rate_limited"));
            }
            Err(RateLimitError::Redis(error)) => {
                tracing::error!(%error, "Password change rate limit unavailable");
                return Err(ManagementError::Credential(error));
            }
        }
        if new_password != confirm_password {
            return Err(ManagementError::Invalid("password_mismatch"));
        }
        self.state
            .config
            .password
            .validate_password(new_password)
            .map_err(ManagementError::Validation)?;

        let verified = identities::Entity::find()
            .filter(identities::Column::UserId.eq(session.user_id))
            .filter(identities::Column::Kind.eq(IdentityKind::Password))
            .filter(identities::Column::UnboundAt.is_null())
            .one(&self.state.db)
            .await?;
        if let Some(identity) = &verified
            && !PasswordIdentityService::verify_password_hash(
                old_password.unwrap_or_default(),
                identity.password_hash.as_deref(),
            )
            .await?
        {
            return Err(ManagementError::Invalid("invalid_credentials"));
        }
        let password_hash = PasswordIdentityService::hash_password(new_password).await?;
        let txn = self.state.db.begin().await?;
        let user = PasswordIdentityService::lock_user(&txn, session.user_id).await?;
        let active_session = crate::db::helper::session::active_query(
            time::OffsetDateTime::now_utc(),
            self.state.config.sso.session_idle_ttl_seconds,
        )
        .filter(sso_sessions::Column::Id.eq(session.id))
        .one(&txn)
        .await?;
        if user.status != UserStatus::Active || active_session.is_none() {
            return Err(ManagementError::Invalid("unauthorized"));
        }
        let now = time::OffsetDateTime::now_utc();
        if let Some(identity) = verified {
            PasswordIdentityService::ensure_unchanged(&txn, &identity)
                .await
                .map_err(|error| match error {
                    sea_orm::DbErr::Custom(_) => ManagementError::Invalid("invalid_credentials"),
                    error => error.into(),
                })?;
            PasswordIdentityService::update_hashed(&txn, identity, password_hash, now).await?;
        } else {
            // A concurrent first-password change must not be overwritten without its password.
            if identities::Entity::find()
                .filter(identities::Column::UserId.eq(session.user_id))
                .filter(identities::Column::Kind.eq(IdentityKind::Password))
                .filter(identities::Column::UnboundAt.is_null())
                .one(&txn)
                .await?
                .is_some()
            {
                return Err(ManagementError::Invalid("invalid_credentials"));
            }
            let provider = crate::db::helper::identity_provider::find_local_provider(&txn).await?;
            PasswordIdentityService::create_hashed(
                &txn,
                session.user_id,
                provider.id,
                session.user_id.to_string(),
                password_hash,
                now,
            )
            .await?;
        }
        super::session::SessionService::revoke_all_login_state_for_user_in_db(
            &txn,
            session.user_id,
            "password_change",
        )
        .await?;
        super::security::notify(&txn, &user, "password_changed").await?;
        txn.commit().await?;
        Ok(())
    }

    pub async fn inspect_password_reset_token(
        &self,
        token: &str,
    ) -> Result<bool, PasswordResetError> {
        self.verify_password_reset_token(token)?;
        self.reset_token_is_usable(token).await
    }

    pub fn verify_password_reset_token(&self, token: &str) -> Result<Uuid, PasswordResetError> {
        if token.is_empty() {
            return Err(PasswordResetError::MissingToken);
        }

        let claims = pero_utils::oauth::jwt::verify_password_reset_token(
            token,
            self.state.config.password_reset.signing_key.expose_secret(),
        )
        .map_err(|_| PasswordResetError::InvalidToken)?;

        if claims.purpose != "password_reset" {
            return Err(PasswordResetError::InvalidToken);
        }

        Uuid::parse_str(&claims.sub).map_err(|_| PasswordResetError::InvalidToken)
    }

    pub async fn reset_password(
        &self,
        token: &str,
        new_password: &str,
        confirm_password: &str,
    ) -> Result<(), PasswordResetError> {
        let user_id = self.verify_password_reset_token(token)?;

        if new_password != confirm_password {
            return Err(PasswordResetError::PasswordMismatch);
        }

        if let Err(e) = self.state.config.password.validate_password(new_password) {
            return Err(PasswordResetError::InvalidPassword(e));
        }

        self.ensure_active_user(user_id).await?;

        let now = time::OffsetDateTime::now_utc();
        let token_hash = pero_utils::crypto::sha256_hex(token);

        use crate::db::entity::password_reset_tokens as prt;

        let hash_result = PasswordIdentityService::hash_password(new_password)
            .await
            .map_err(|e| {
                tracing::error!("Password hash error: {e}");
                PasswordResetError::Internal
            })?;

        let txn = self.state.db.begin().await.map_err(|e| {
            tracing::error!("Reset password transaction begin error: {e}");
            PasswordResetError::Internal
        })?;

        let user = PasswordIdentityService::lock_user(&txn, user_id)
            .await
            .map_err(|_| PasswordResetError::Internal)?;
        if user.status != UserStatus::Active {
            return Err(PasswordResetError::InvalidToken);
        }

        let _reset_token = match prt::Entity::find()
            .filter(prt::Column::TokenHash.eq(&token_hash))
            .filter(prt::Column::UserId.eq(user_id))
            .filter(prt::Column::ConsumedAt.is_null())
            .filter(prt::Column::ExpiresAt.gt(now))
            .lock_exclusive()
            .one(&txn)
            .await
        {
            Ok(Some(model)) => model,
            Ok(None) => return Err(PasswordResetError::TokenAlreadyUsed),
            Err(e) => {
                tracing::error!("Reset token lock error: {e}");
                return Err(PasswordResetError::Internal);
            }
        };

        let identity = PasswordIdentityService::find(&txn, user_id)
            .await
            .map_err(|_| PasswordResetError::Internal)?;
        let password_update = async {
            if let Some(identity) = identity {
                PasswordIdentityService::update_hashed(&txn, identity, hash_result, now).await?;
            } else {
                let provider =
                    crate::db::helper::identity_provider::find_local_provider(&txn).await?;
                PasswordIdentityService::create_hashed(
                    &txn,
                    user_id,
                    provider.id,
                    user_id.to_string(),
                    hash_result,
                    now,
                )
                .await?;
            }
            Ok::<_, sea_orm::DbErr>(())
        }
        .await;
        password_update.map_err(|error| {
            tracing::error!(%error, "Password recovery failed");
            PasswordResetError::Internal
        })?;

        crate::service::contact::invalidate_contact_credentials(&txn, user_id, None)
            .await
            .map_err(|_| PasswordResetError::Internal)?;

        if let Err(e) =
            crate::service::session::SessionService::revoke_all_login_state_for_user_in_db(
                &txn,
                user_id,
                "password_reset",
            )
            .await
        {
            tracing::error!("Session revoke error during password reset: {e}");
            return Err(PasswordResetError::Internal);
        }

        super::security::notify(&txn, &user, "password_reset_completed")
            .await
            .map_err(|_| PasswordResetError::Internal)?;
        if let Err(e) = txn.commit().await {
            tracing::error!("Reset password transaction commit error: {e}");
            return Err(PasswordResetError::Internal);
        }

        Ok(())
    }

    async fn reset_token_is_usable(&self, token: &str) -> Result<bool, PasswordResetError> {
        let now = time::OffsetDateTime::now_utc();
        let token_hash = pero_utils::crypto::sha256_hex(token);
        let token = crate::db::entity::password_reset_tokens::Entity::find()
            .filter(crate::db::entity::password_reset_tokens::Column::TokenHash.eq(token_hash))
            .filter(crate::db::entity::password_reset_tokens::Column::ConsumedAt.is_null())
            .filter(crate::db::entity::password_reset_tokens::Column::ExpiresAt.gt(now))
            .one(&self.state.db)
            .await
            .map_err(|e| {
                tracing::error!("Reset token lookup error: {e}");
                PasswordResetError::Internal
            })?;
        Ok(token.is_some())
    }

    async fn ensure_active_user(&self, user_id: Uuid) -> Result<(), PasswordResetError> {
        match users::Entity::find_by_id(user_id).one(&self.state.db).await {
            Ok(Some(user)) if user.deleted_at.is_none() && user.status == UserStatus::Active => {
                Ok(())
            }
            Ok(_) => Err(PasswordResetError::InvalidToken),
            Err(e) => {
                tracing::error!("Reset password user lookup error: {e}");
                Err(PasswordResetError::Internal)
            }
        }
    }
}
