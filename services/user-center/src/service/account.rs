use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, QuerySelect, Set, TransactionTrait,
};
use uuid::Uuid;

use crate::db::entity::users;
use crate::db::enums::{IdentityKind, UserStatus};
use crate::service::access::insert_auto_access;
use crate::service::password::PasswordIdentityService;
use crate::state::app::AppState;

pub struct RegisterUserParams {
    pub username: String,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub nickname: Option<String>,
    pub password: String,
    pub auth_request_id: Option<Uuid>,
}

pub enum RegisterUserError {
    InvalidUsername(String),
    InvalidPassword(String),
    UsernameTaken,
    EmailTaken,
    PhoneTaken,
    Internal,
}

impl RegisterUserError {
    pub fn message_key(&self) -> &str {
        match self {
            Self::InvalidUsername(msg) | Self::InvalidPassword(msg) => msg.as_str(),
            Self::UsernameTaken => "username_taken",
            Self::EmailTaken => "email_taken",
            Self::PhoneTaken => "phone_taken",
            Self::Internal => "internal_error",
        }
    }
}

pub struct PasswordResetTokenStatus {
    pub user_id: Uuid,
    pub usable: bool,
}

pub enum PasswordResetError {
    MissingToken,
    InvalidToken,
    TokenAlreadyUsed,
    PasswordMismatch,
    InvalidPassword(String),
    RateLimited,
    ServiceUnavailable,
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
            Self::RateLimited => "rate_limited",
            Self::ServiceUnavailable => "service_unavailable",
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

    pub async fn register_user(
        &self,
        mut params: RegisterUserParams,
    ) -> Result<(), RegisterUserError> {
        params.username = params.username.trim().to_owned();
        if let Err(e) = crate::db::helper::user::validate_username(&params.username) {
            return Err(RegisterUserError::InvalidUsername(e));
        }

        if params.password.trim().is_empty() {
            return Err(RegisterUserError::InvalidPassword(
                "password is required".to_owned(),
            ));
        }

        if let Err(e) = self
            .state
            .config
            .password
            .validate_password(&params.password)
        {
            return Err(RegisterUserError::InvalidPassword(e));
        }

        self.ensure_unique_user_fields(&params).await?;

        let password_hash = PasswordIdentityService::hash_password(&params.password)
            .await
            .map_err(|_| RegisterUserError::Internal)?;

        let txn = self.state.db.begin().await.map_err(|e| {
            tracing::error!("Registration transaction begin error: {e}");
            RegisterUserError::Internal
        })?;

        let user_id = Uuid::now_v7();
        let now = time::OffsetDateTime::now_utc();
        let user_model = users::ActiveModel {
            id: Set(user_id),
            username: Set(params.username.clone()),
            email: Set(params.email.clone()),
            email_verified_at: Set(None),
            phone: Set(params.phone.clone()),
            phone_verified_at: Set(None),
            nickname: Set(params.nickname.clone()),
            avatar_url: Set(None),
            status: Set(UserStatus::Active),
            created_at: Set(now),
            updated_at: Set(now),
            deleted_at: Set(None),
        };

        if let Err(e) = user_model.insert(&txn).await {
            tracing::error!("User insert error: {e}");
            let _ = txn.rollback().await;
            return Err(registration_unique_error(&e).unwrap_or(RegisterUserError::Internal));
        }

        let provider = match crate::db::helper::identity_provider::find_local_provider(&txn).await {
            Ok(provider) => provider,
            Err(e) => {
                tracing::error!("Local provider not found: {e}");
                let _ = txn.rollback().await;
                return Err(RegisterUserError::Internal);
            }
        };

        if let Err(e) = PasswordIdentityService::create_hashed(
            &txn,
            user_id,
            provider.id,
            user_id.to_string(),
            password_hash,
            now,
        )
        .await
        {
            tracing::error!("Identity insert error: {e}");
            let _ = txn.rollback().await;
            return Err(RegisterUserError::Internal);
        }

        if let Err(e) = insert_auto_access(&txn, user_id, params.auth_request_id, now).await {
            tracing::error!("Auto app access insert error: {e}");
            let _ = txn.rollback().await;
            return Err(RegisterUserError::Internal);
        }

        if let Err(e) = txn.commit().await {
            tracing::error!("Registration transaction commit error: {e}");
            return Err(RegisterUserError::Internal);
        }

        Ok(())
    }

    async fn ensure_unique_user_fields(
        &self,
        params: &RegisterUserParams,
    ) -> Result<(), RegisterUserError> {
        if user_field_exists(users::Column::Username, &params.username, self.state).await? {
            return Err(RegisterUserError::UsernameTaken);
        }

        if let Some(ref email) = params.email
            && user_field_exists(users::Column::Email, email, self.state).await?
        {
            return Err(RegisterUserError::EmailTaken);
        }

        if let Some(ref phone) = params.phone
            && user_field_exists(users::Column::Phone, phone, self.state).await?
        {
            return Err(RegisterUserError::PhoneTaken);
        }

        Ok(())
    }

    pub async fn inspect_password_reset_token(
        &self,
        token: &str,
    ) -> Result<PasswordResetTokenStatus, PasswordResetError> {
        let user_id = self.verify_password_reset_token(token)?;
        let usable = self.reset_token_is_usable(token).await?;
        Ok(PasswordResetTokenStatus { user_id, usable })
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

        use crate::db::entity::identities::{Column, Entity};
        use crate::db::entity::password_reset_tokens as prt;
        use sea_orm::sea_query::Expr;

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

        let password_update = Entity::update_many()
            .col_expr(Column::PasswordHash, Expr::value(Some(hash_result.hash)))
            .col_expr(
                Column::PasswordAlgorithm,
                Expr::value(Some(hash_result.algorithm)),
            )
            .col_expr(Column::PasswordUpdatedAt, Expr::value(Some(now)))
            .filter(Column::UserId.eq(user_id))
            .filter(Column::Kind.eq(IdentityKind::Password))
            .filter(Column::UnboundAt.is_null())
            .exec(&txn)
            .await;

        match password_update {
            Ok(r) if r.rows_affected > 0 => {}
            Ok(_) => return Err(PasswordResetError::InvalidToken),
            Err(e) => {
                tracing::error!("Password update error: {e}");
                return Err(PasswordResetError::Internal);
            }
        }

        crate::service::recovery::invalidate(&txn, user_id)
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

async fn user_field_exists(
    column: users::Column,
    value: &str,
    state: &AppState,
) -> Result<bool, RegisterUserError> {
    users::Entity::find()
        .filter(column.eq(value))
        .filter(users::Column::DeletedAt.is_null())
        .one(&state.db)
        .await
        .map(|row| row.is_some())
        .map_err(|e| {
            tracing::error!("User uniqueness check DB error: {e}");
            RegisterUserError::Internal
        })
}

fn registration_unique_error(err: &sea_orm::DbErr) -> Option<RegisterUserError> {
    if !crate::db::error::is_unique_violation(err) {
        return None;
    }

    let msg = err.to_string().to_lowercase();
    if msg.contains("ux_users_username_alive") || msg.contains("users_username") {
        Some(RegisterUserError::UsernameTaken)
    } else if msg.contains("ux_users_email_alive") || msg.contains("users_email") {
        Some(RegisterUserError::EmailTaken)
    } else if msg.contains("ux_users_phone_alive") || msg.contains("users_phone") {
        Some(RegisterUserError::PhoneTaken)
    } else {
        Some(RegisterUserError::Internal)
    }
}
