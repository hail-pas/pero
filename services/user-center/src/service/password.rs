use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DbErr, EntityTrait, QueryFilter, QuerySelect,
    Set,
};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::db::entity::identities;
use crate::db::enums::IdentityKind;

pub struct PasswordIdentityService;

impl PasswordIdentityService {
    pub async fn find<C: ConnectionTrait>(
        db: &C,
        user_id: Uuid,
    ) -> Result<Option<identities::Model>, DbErr> {
        identities::Entity::find()
            .filter(identities::Column::UserId.eq(user_id))
            .filter(identities::Column::Kind.eq(IdentityKind::Password))
            .filter(identities::Column::UnboundAt.is_null())
            .one(db)
            .await
    }

    pub async fn hash_password(
        password: &str,
    ) -> Result<pero_utils::crypto::password::PasswordHashResult, pero_error::AppError> {
        let password = password.to_owned();
        pero_utils::crypto::run_crypto(move || {
            pero_utils::crypto::password::hash_password(&password).map_err(|_| {
                pero_error::AppError::internal("password_hash_failed", "Password hashing failed")
            })
        })
        .await
    }

    pub async fn verify_password_hash(
        password: &str,
        hash: Option<&str>,
    ) -> Result<bool, pero_error::AppError> {
        let Some(hash) = hash.filter(|value| !value.is_empty()) else {
            return Ok(false);
        };
        let (password, hash) = (password.to_owned(), hash.to_owned());
        pero_utils::crypto::run_crypto(move || {
            Ok(pero_utils::crypto::password::verify_password(&password, &hash).unwrap_or(false))
        })
        .await
    }

    /// Serialize all credential changes and reset-token issuance by user, before any token lock.
    pub async fn lock_user<C: ConnectionTrait>(
        db: &C,
        user_id: Uuid,
    ) -> Result<crate::db::entity::users::Model, DbErr> {
        use crate::db::entity::users;
        users::Entity::find_by_id(user_id)
            .filter(users::Column::DeletedAt.is_null())
            .lock_exclusive()
            .one(db)
            .await?
            .ok_or_else(|| DbErr::RecordNotFound("user not found".into()))
    }

    pub async fn ensure_unchanged<C: ConnectionTrait>(
        db: &C,
        verified: &identities::Model,
    ) -> Result<(), DbErr> {
        let current = identities::Entity::find_by_id(verified.id).one(db).await?;
        if current.is_none_or(|current| {
            current.unbound_at.is_some()
                || current.password_hash != verified.password_hash
                || current.password_updated_at != verified.password_updated_at
        }) {
            return Err(DbErr::Custom("credentials_changed".into()));
        }
        Ok(())
    }

    pub async fn invalidate_reset_tokens<C: ConnectionTrait>(
        db: &C,
        user_id: Uuid,
    ) -> Result<(), DbErr> {
        crate::service::recovery::invalidate(db, user_id).await
    }

    pub async fn create<C>(
        db: &C,
        user_id: Uuid,
        provider_id: Uuid,
        subject: String,
        password: &str,
        now: OffsetDateTime,
    ) -> Result<identities::Model, DbErr>
    where
        C: ConnectionTrait,
    {
        let hash_result = Self::hash_password(password)
            .await
            .map_err(|error| DbErr::Custom(error.to_string()))?;
        Self::create_hashed(db, user_id, provider_id, subject, hash_result, now).await
    }

    pub async fn create_hashed<C: ConnectionTrait>(
        db: &C,
        user_id: Uuid,
        provider_id: Uuid,
        subject: String,
        hash_result: pero_utils::crypto::password::PasswordHashResult,
        now: OffsetDateTime,
    ) -> Result<identities::Model, DbErr> {
        let identity = identities::ActiveModel {
            id: Set(Uuid::now_v7()),
            user_id: Set(user_id),
            provider_id: Set(provider_id),
            kind: Set(IdentityKind::Password),
            subject: Set(subject),
            password_hash: Set(Some(hash_result.hash)),
            password_algorithm: Set(Some(hash_result.algorithm)),
            password_updated_at: Set(Some(now)),
            profile: Set(serde_json::json!({})),
            last_login_at: Set(None),
            created_at: Set(now),
            updated_at: Set(now),
            unbound_at: Set(None),
        };
        Self::invalidate_reset_tokens(db, user_id).await?;
        identity.insert(db).await
    }

    pub async fn update_hashed<C: ConnectionTrait>(
        db: &C,
        identity: identities::Model,
        hash_result: pero_utils::crypto::password::PasswordHashResult,
        now: OffsetDateTime,
    ) -> Result<identities::Model, DbErr> {
        Self::invalidate_reset_tokens(db, identity.user_id).await?;
        let mut active: identities::ActiveModel = identity.into();
        active.password_hash = Set(Some(hash_result.hash));
        active.password_algorithm = Set(Some(hash_result.algorithm));
        active.password_updated_at = Set(Some(now));
        active.updated_at = Set(now);
        active.update(db).await
    }
}
