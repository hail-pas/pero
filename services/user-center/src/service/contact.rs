use pero_cache_redis::RedisCacheStore;
use pero_cache_redis::rate_limit::{RateLimitError, enforce_rate_limit};
use pero_cache_redis::rate_limit_key::{rl_verify_attempt, rl_verify_send};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QuerySelect, Set,
    TransactionTrait,
};
use uuid::Uuid;

use crate::db::entity::{contact_change_requests as ccr, users};
use crate::db::enums::{ContactChangeStatus, ContactChangeType, UserStatus};

pub enum ContactError {
    UserNotFound,
    AlreadyVerified,
    NoValue,
    Required,
    SameValue,
    SamePendingValue,
    ContactTaken,
    RateLimited,
    ServiceUnavailable,
    InvalidNonce,
    InvalidCode,
    CodeExpired,
    SendFailed,
    Internal(String),
}

#[derive(Clone, Copy)]
pub enum ContactChannel {
    Email,
    Phone,
}

impl ContactChannel {
    pub fn change_type(self) -> ContactChangeType {
        match self {
            Self::Email => ContactChangeType::Email,
            Self::Phone => ContactChangeType::Phone,
        }
    }

    pub fn key(self) -> &'static str {
        match self {
            Self::Email => "email",
            Self::Phone => "phone",
        }
    }

    pub fn current_value(self, user: &users::Model) -> Option<&str> {
        match self {
            Self::Email => user.email.as_deref().filter(|value| !value.is_empty()),
            Self::Phone => user.phone.as_deref().filter(|value| !value.is_empty()),
        }
    }

    pub fn is_verified(self, user: &users::Model) -> bool {
        match self {
            Self::Email => user.email_verified_at.is_some(),
            Self::Phone => user.phone_verified_at.is_some(),
        }
    }

    pub fn is_valid_format(self, value: &str) -> bool {
        match self {
            Self::Email => {
                if !validator::ValidateEmail::validate_email(&value) {
                    return false;
                }
                value.rsplit_once('@').is_some_and(|(_, domain)| {
                    let domain = domain.trim_start_matches('[').trim_end_matches(']');
                    !domain.starts_with('.')
                        && domain.contains('.')
                        && domain.split('.').all(|p| !p.is_empty())
                        && !domain.chars().all(|c| c.is_ascii_digit() || c == '.')
                })
            }
            Self::Phone => {
                let digits = value.strip_prefix('+').unwrap_or(value);
                !digits.is_empty()
                    && digits.chars().all(|c| c.is_ascii_digit())
                    && digits.len() >= 7
            }
        }
    }

    pub fn apply_user_contact_update(
        self,
        user: &users::Model,
        active: &mut users::ActiveModel,
        new_value: Option<String>,
    ) {
        match self {
            Self::Email => {
                if user.email != new_value {
                    active.email_verified_at = Set(None);
                }
                active.email = Set(new_value);
            }
            Self::Phone => {
                if user.phone != new_value {
                    active.phone_verified_at = Set(None);
                }
                active.phone = Set(new_value);
            }
        }
    }
}

pub struct ContactVerificationService<'a> {
    db: &'a DatabaseConnection,
    cache: &'a RedisCacheStore,
}

impl<'a> ContactVerificationService<'a> {
    pub fn new(db: &'a DatabaseConnection, cache: &'a RedisCacheStore) -> Self {
        Self { db, cache }
    }

    pub async fn load_active_user(&self, user_id: Uuid) -> Result<users::Model, ContactError> {
        match users::Entity::find_by_id(user_id).one(self.db).await {
            Ok(Some(user)) if user.status == UserStatus::Active && user.deleted_at.is_none() => {
                Ok(user)
            }
            _ => Err(ContactError::UserNotFound),
        }
    }

    async fn is_contact_taken_db<C: sea_orm::ConnectionTrait>(
        &self,
        channel: ContactChannel,
        value: &str,
        self_id: Uuid,
        db: &C,
    ) -> Result<bool, ContactError> {
        let user_column = match channel {
            ContactChannel::Email => users::Column::Email,
            ContactChannel::Phone => users::Column::Phone,
        };

        if users::Entity::find()
            .filter(user_column.eq(value))
            .filter(users::Column::Id.ne(self_id))
            .filter(users::Column::DeletedAt.is_null())
            .one(db)
            .await
            .map_err(|_| ContactError::ServiceUnavailable)?
            .is_some()
        {
            return Ok(true);
        }

        Ok(ccr::Entity::find()
            .filter(ccr::Column::ChangeType.eq(channel.change_type()))
            .filter(ccr::Column::NewValue.eq(value))
            .filter(ccr::Column::UserId.ne(self_id))
            .filter(ccr::Column::Status.eq(ContactChangeStatus::Pending))
            .filter(ccr::Column::ExpiresAt.gt(time::OffsetDateTime::now_utc()))
            .one(db)
            .await
            .map_err(|_| ContactError::ServiceUnavailable)?
            .is_some())
    }

    pub async fn has_pending_same_value_in_txn<C: sea_orm::ConnectionTrait>(
        &self,
        user_id: Uuid,
        change_type: ContactChangeType,
        value: &str,
        db: &C,
    ) -> Result<bool, ContactError> {
        Ok(ccr::Entity::find()
            .filter(ccr::Column::UserId.eq(user_id))
            .filter(ccr::Column::ChangeType.eq(change_type))
            .filter(ccr::Column::Status.eq(ContactChangeStatus::Pending))
            .filter(ccr::Column::ExpiresAt.gt(time::OffsetDateTime::now_utc()))
            .filter(ccr::Column::NewValue.eq(value))
            .one(db)
            .await
            .map_err(|_| ContactError::ServiceUnavailable)?
            .is_some())
    }

    pub async fn check_rate_limit(
        &self,
        user_id: Uuid,
        change_type: &str,
    ) -> Result<(), ContactError> {
        let key = rl_verify_send
            .key(&user_id.to_string(), change_type)
            .map_err(|e| ContactError::Internal(e.to_string()))?;
        map_rate_limit_result(enforce_rate_limit(self.cache, &key, 5).await)
    }

    pub async fn check_verify_attempt_limit(
        &self,
        user_id: Uuid,
        nonce: &str,
    ) -> Result<(), ContactError> {
        let key = rl_verify_attempt
            .key(&user_id.to_string(), nonce)
            .map_err(|e| ContactError::Internal(e.to_string()))?;
        map_rate_limit_result(enforce_rate_limit(self.cache, &key, 10).await)
    }

    pub async fn create_contact_request(
        &mut self,
        user_id: Uuid,
        channel: ContactChannel,
        value: String,
        notification_base_url: Option<&str>,
    ) -> Result<(String, String), ContactError> {
        let txn = self.db.begin().await.map_err(|e| {
            tracing::error!("Transaction begin: {e}");
            ContactError::Internal("internal_error".into())
        })?;

        crate::service::password::PasswordIdentityService::lock_user(&txn, user_id)
            .await
            .map_err(|_| ContactError::ServiceUnavailable)?;
        let now = time::OffsetDateTime::now_utc();
        // Release expired reservations in the same transaction before the unique indexes are checked.
        ccr::Entity::update_many()
            .col_expr(
                ccr::Column::Status,
                sea_orm::sea_query::Expr::value(ContactChangeStatus::Expired),
            )
            .col_expr(ccr::Column::UpdatedAt, sea_orm::sea_query::Expr::value(now))
            .filter(ccr::Column::ChangeType.eq(channel.change_type()))
            .filter(ccr::Column::Status.eq(ContactChangeStatus::Pending))
            .filter(ccr::Column::ExpiresAt.lte(now))
            .filter(
                sea_orm::Condition::any()
                    .add(ccr::Column::UserId.eq(user_id))
                    .add(ccr::Column::NewValue.eq(&value)),
            )
            .exec(&txn)
            .await
            .map_err(|_| ContactError::ServiceUnavailable)?;

        if self
            .has_pending_same_value_in_txn(user_id, channel.change_type(), &value, &txn)
            .await?
        {
            let _ = txn.rollback().await;
            return Err(ContactError::SamePendingValue);
        }

        if self
            .is_contact_taken_db(channel, &value, user_id, &txn)
            .await?
        {
            let _ = txn.rollback().await;
            return Err(ContactError::ContactTaken);
        }

        let verification = crate::service::verification::generate_code();

        {
            let pending = ccr::Entity::find()
                .filter(ccr::Column::UserId.eq(user_id))
                .filter(ccr::Column::ChangeType.eq(channel.change_type()))
                .filter(ccr::Column::Status.eq(ContactChangeStatus::Pending))
                .all(&txn)
                .await
                .map_err(|e| {
                    tracing::error!("Find pending: {e}");
                    ContactError::Internal("internal_error".into())
                })?;
            for m in pending {
                ccr::Entity::delete_by_id(m.id)
                    .exec(&txn)
                    .await
                    .map_err(|e| {
                        tracing::error!("Cancel pending: {e}");
                        ContactError::Internal("internal_error".into())
                    })?;
            }
        }

        let now = time::OffsetDateTime::now_utc();
        let existing = ccr::Entity::find()
            .filter(ccr::Column::UserId.eq(user_id))
            .filter(ccr::Column::ChangeType.eq(channel.change_type()))
            .filter(ccr::Column::NewValue.eq(&value))
            .one(&txn)
            .await;
        match existing {
            Ok(Some(model)) => {
                let mut active: ccr::ActiveModel = model.into();
                active.status = Set(ContactChangeStatus::Pending);
                active.verification_code_hash = Set(verification.code_hash.clone());
                active.nonce = Set(verification.nonce.clone());
                active.requested_at = Set(now);
                active.expires_at = Set(crate::service::verification::expires_in(
                    time::Duration::minutes(15),
                ));
                active.verified_at = Set(None);
                active.cancelled_at = Set(None);
                active.updated_at = Set(now);
                if let Err(e) = active.update(&txn).await {
                    tracing::error!("Contact change update: {e}");
                    return Err(ContactError::Internal("internal_error".into()));
                }
            }
            Ok(None) => {
                let req = ccr::ActiveModel {
                    id: Set(Uuid::now_v7()),
                    user_id: Set(user_id),
                    change_type: Set(channel.change_type()),
                    new_value: Set(value.clone()),
                    status: Set(ContactChangeStatus::Pending),
                    verification_code_hash: Set(verification.code_hash.clone()),
                    nonce: Set(verification.nonce.clone()),
                    requested_at: Set(now),
                    expires_at: Set(crate::service::verification::expires_in(
                        time::Duration::minutes(15),
                    )),
                    verified_at: Set(None),
                    cancelled_at: Set(None),
                    created_at: Set(now),
                    updated_at: Set(now),
                };
                if let Err(e) = req.insert(&txn).await {
                    tracing::error!("Contact change insert: {e}");
                    return Err(ContactError::Internal("internal_error".into()));
                }
            }
            Err(e) => {
                tracing::error!("Contact change lookup: {e}");
                return Err(ContactError::Internal("internal_error".into()));
            }
        }

        if let Some(base_url) = notification_base_url {
            crate::service::notify::enqueue_verification(
                &txn,
                user_id,
                base_url,
                channel.key(),
                &value,
                &verification.code,
                &verification.nonce,
            )
            .await
            .map_err(|_| ContactError::SendFailed)?;
        }

        txn.commit().await.map_err(|e| {
            tracing::error!("Transaction commit: {e}");
            ContactError::Internal("internal_error".into())
        })?;

        Ok((verification.code, verification.nonce))
    }

    pub async fn verify_contact(
        &self,
        user_id: Uuid,
        nonce: &str,
        code: &str,
    ) -> Result<ContactChangeType, ContactError> {
        let req = match ccr::Entity::find()
            .filter(ccr::Column::Nonce.eq(nonce))
            .filter(ccr::Column::Status.eq(ContactChangeStatus::Pending))
            .one(self.db)
            .await
        {
            Ok(Some(r)) => r,
            Ok(None) => return Err(ContactError::InvalidNonce),
            Err(e) => {
                tracing::error!("Find change request: {e}");
                return Err(ContactError::Internal("internal_error".into()));
            }
        };

        if req.user_id != user_id {
            return Err(ContactError::InvalidNonce);
        }

        self.check_verify_attempt_limit(user_id, nonce).await?;

        let txn = match self.db.begin().await {
            Ok(t) => t,
            Err(e) => {
                tracing::error!("Transaction begin: {e}");
                return Err(ContactError::Internal("internal_error".into()));
            }
        };

        let user = match users::Entity::find_by_id(user_id)
            .lock_exclusive()
            .one(&txn)
            .await
        {
            Ok(Some(user)) if user.status == UserStatus::Active && user.deleted_at.is_none() => {
                user
            }
            Ok(_) => return Err(ContactError::UserNotFound),
            Err(e) => {
                tracing::error!("Load active user for contact verification: {e}");
                return Err(ContactError::Internal("internal_error".into()));
            }
        };

        let req = match ccr::Entity::find()
            .filter(ccr::Column::Nonce.eq(nonce))
            .filter(ccr::Column::Status.eq(ContactChangeStatus::Pending))
            .lock_exclusive()
            .one(&txn)
            .await
        {
            Ok(Some(r)) => r,
            Ok(None) => return Err(ContactError::InvalidNonce),
            Err(e) => {
                tracing::error!("Find change request for verification: {e}");
                return Err(ContactError::Internal("internal_error".into()));
            }
        };

        if req.user_id != user_id {
            return Err(ContactError::InvalidNonce);
        }

        let code_hash = pero_utils::crypto::sha256_hex(code.trim());
        if req.verification_code_hash != code_hash {
            return Err(ContactError::InvalidCode);
        }

        if req.expires_at <= time::OffsetDateTime::now_utc() {
            return Err(ContactError::CodeExpired);
        }

        let now = time::OffsetDateTime::now_utc();
        let req_id = req.id;
        let change_type = req.change_type.clone();
        let new_value = req.new_value.clone();
        drop(req);

        let contact_column = match change_type {
            ContactChangeType::Email => users::Column::Email,
            ContactChangeType::Phone => users::Column::Phone,
        };

        let contact_taken = match users::Entity::find()
            .filter(contact_column.eq(&new_value))
            .filter(users::Column::Id.ne(user_id))
            .filter(users::Column::DeletedAt.is_null())
            .one(&txn)
            .await
        {
            Ok(row) => row.is_some(),
            Err(e) => {
                tracing::error!("Check verified contact conflict: {e}");
                return Err(ContactError::Internal("internal_error".into()));
            }
        };
        if contact_taken {
            return Err(ContactError::ContactTaken);
        }

        let contact_changed = match change_type {
            ContactChangeType::Email => user.email.as_deref() != Some(new_value.as_str()),
            ContactChangeType::Phone => user.phone.as_deref() != Some(new_value.as_str()),
        };
        let mut user_active: users::ActiveModel = user.into();
        user_active.updated_at = Set(now);
        match change_type {
            ContactChangeType::Email => {
                user_active.email = Set(Some(new_value));
                user_active.email_verified_at = Set(Some(now));
            }
            ContactChangeType::Phone => {
                user_active.phone = Set(Some(new_value));
                user_active.phone_verified_at = Set(Some(now));
            }
        }

        if let Err(e) = user_active.update(&txn).await {
            tracing::error!("Update user contact: {e}");
            if crate::db::error::is_unique_violation(&e) {
                return Err(ContactError::ContactTaken);
            }
            return Err(ContactError::Internal("internal_error".into()));
        }

        if contact_changed {
            invalidate_contact_credentials(&txn, user_id, Some(req_id))
                .await
                .map_err(|_| ContactError::ServiceUnavailable)?;
        }

        let verified_req = ccr::ActiveModel {
            id: Set(req_id),
            status: Set(ContactChangeStatus::Verified),
            verified_at: Set(Some(now)),
            updated_at: Set(now),
            ..Default::default()
        };
        if let Err(e) = verified_req.update(&txn).await {
            tracing::error!("Update change request: {e}");
            return Err(ContactError::Internal("internal_error".into()));
        }

        if let Err(e) = txn.commit().await {
            tracing::error!("Transaction commit: {e}");
            return Err(ContactError::Internal("internal_error".into()));
        }

        Ok(change_type)
    }

    pub async fn cancel_contact(&self, user_id: Uuid, nonce: &str) -> Result<(), ContactError> {
        let req = match ccr::Entity::find()
            .filter(ccr::Column::Nonce.eq(nonce))
            .filter(ccr::Column::Status.eq(ContactChangeStatus::Pending))
            .one(self.db)
            .await
        {
            Ok(Some(r)) => r,
            Ok(None) => return Err(ContactError::InvalidNonce),
            Err(e) => {
                tracing::error!("Find change request: {e}");
                return Err(ContactError::Internal("internal_error".into()));
            }
        };

        if req.user_id != user_id {
            return Err(ContactError::InvalidNonce);
        }

        let req_id = req.id;

        let txn = match self.db.begin().await {
            Ok(t) => t,
            Err(e) => {
                tracing::error!("Transaction begin: {e}");
                return Err(ContactError::Internal("internal_error".into()));
            }
        };

        if let Err(e) = ccr::Entity::delete_by_id(req_id).exec(&txn).await {
            tracing::error!("Delete change request: {e}");
            return Err(ContactError::Internal("internal_error".into()));
        }
        if let Err(e) = txn.commit().await {
            tracing::error!("Transaction commit: {e}");
            return Err(ContactError::Internal("internal_error".into()));
        }

        Ok(())
    }

    pub async fn load_pending_request(
        &self,
        nonce: &str,
    ) -> Result<Option<ccr::Model>, ContactError> {
        match ccr::Entity::find()
            .filter(ccr::Column::Nonce.eq(nonce))
            .filter(ccr::Column::Status.eq(ContactChangeStatus::Pending))
            .one(self.db)
            .await
        {
            Ok(r) => Ok(r),
            Err(e) => {
                tracing::error!("Find pending request: {e}");
                Err(ContactError::Internal("internal_error".into()))
            }
        }
    }
}

fn map_rate_limit_result(result: Result<(), RateLimitError>) -> Result<(), ContactError> {
    match result {
        Ok(()) => Ok(()),
        Err(RateLimitError::Denied { .. }) => Err(ContactError::RateLimited),
        Err(RateLimitError::Redis(e)) => {
            tracing::error!(error = %e, "rate_limit_check redis error");
            Err(ContactError::ServiceUnavailable)
        }
    }
}

/// Shared by self-service verification and administrator contact replacement.
/// The caller holds the user lock and commits this with the users update.
pub async fn invalidate_contact_credentials<C: sea_orm::ConnectionTrait>(
    db: &C,
    user_id: Uuid,
    completing: Option<Uuid>,
) -> Result<(), sea_orm::DbErr> {
    crate::service::recovery::invalidate(db, user_id).await?;
    let mut pending = ccr::Entity::delete_many()
        .filter(ccr::Column::UserId.eq(user_id))
        .filter(ccr::Column::Status.eq(ContactChangeStatus::Pending));
    if let Some(id) = completing {
        pending = pending.filter(ccr::Column::Id.ne(id));
    }
    pending.exec(db).await?;
    db.execute_raw(sea_orm::Statement::from_sql_and_values(
        sea_orm::DbBackend::Postgres,
        "DELETE FROM notification_outbox WHERE user_id = $1 AND kind = 'verify_contact'",
        [user_id.into()],
    ))
    .await?;
    Ok(())
}
