//! Signing-key validation and rotation share the provider's transaction lock.
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DatabaseConnection, EntityTrait, QueryFilter,
    QuerySelect, Set, TransactionTrait,
};
use time::OffsetDateTime;
use uuid::Uuid;

use super::ManagementError;
use crate::db::{
    entity::{identity_provider_keys as keys, identity_providers},
    enums::{KeyAlgorithm, KeyUse},
};

pub struct KeyInput {
    pub kid: String,
    pub algorithm: KeyAlgorithm,
    pub key_use: KeyUse,
    pub public_key_pem: String,
    pub private_key_pem: Option<String>,
    pub certificate_pem: Option<String>,
    pub not_before: Option<OffsetDateTime>,
    pub expires_at: Option<OffsetDateTime>,
    pub active: bool,
}

impl KeyInput {
    fn validate(&self) -> Result<(), ManagementError> {
        if self.kid.is_empty() || self.public_key_pem.is_empty() {
            return Err(ManagementError::Invalid("kid_and_public_key_required"));
        }
        if matches!(self.kid.as_str(), "." | "..") {
            return Err(ManagementError::Invalid("invalid_key_id"));
        }
        if self.algorithm != KeyAlgorithm::Rs256 {
            return Err(ManagementError::Invalid("unsupported_signing_algorithm"));
        }
        if self.key_use != KeyUse::Sig {
            return Err(ManagementError::Invalid("invalid_key_use"));
        }
        if self.active && self.private_key_pem.is_none() {
            return Err(ManagementError::Invalid(
                "private_key_required_for_active_signing_key",
            ));
        }
        if self
            .not_before
            .zip(self.expires_at)
            .is_some_and(|(start, end)| start >= end)
        {
            return Err(ManagementError::Invalid("invalid_key_dates"));
        }
        if self.active && !currently_valid(self.not_before, self.expires_at) {
            return Err(ManagementError::Invalid("key_not_currently_valid"));
        }
        pero_utils::oauth::jwk::validate_signing_key(
            &self.public_key_pem,
            self.private_key_pem.as_deref(),
        )
        .map_err(ManagementError::Validation)
    }
}

fn currently_valid(start: Option<OffsetDateTime>, end: Option<OffsetDateTime>) -> bool {
    let now = OffsetDateTime::now_utc();
    start.is_none_or(|at| at <= now) && end.is_none_or(|at| at > now)
}

pub async fn create(
    db: &DatabaseConnection,
    provider_id: Uuid,
    input: KeyInput,
) -> Result<(), ManagementError> {
    // Validate before touching active keys, including the signing-only invariant.
    input.validate()?;
    let txn = db.begin().await?;
    lock_provider(&txn, provider_id).await?;
    if input.active {
        deactivate_signing_keys(&txn, provider_id).await?;
    }
    let now = OffsetDateTime::now_utc();
    let id = Uuid::now_v7();
    keys::ActiveModel {
        id: Set(id),
        provider_id: Set(provider_id),
        kid: Set(input.kid),
        r#use: Set(input.key_use),
        algorithm: Set(input.algorithm),
        public_key_pem: Set(input.public_key_pem),
        private_key_pem_enc: Set(None),
        certificate_pem: Set(input.certificate_pem),
        active: Set(input.active),
        not_before: Set(input.not_before),
        expires_at: Set(input.expires_at),
        revoked_at: Set(None),
        created_at: Set(now),
        updated_at: Set(now),
    }
    .insert(&txn)
    .await?;
    if let Some(private) = input.private_key_pem {
        crate::db::crypto_expr::update_signing_key_private_key(&txn, &private, id).await?;
    }
    txn.commit().await?;
    Ok(())
}

pub async fn activate(
    db: &DatabaseConnection,
    provider_id: Uuid,
    kid: &str,
) -> Result<(), ManagementError> {
    let txn = db.begin().await?;
    lock_provider(&txn, provider_id).await?;
    let key = keys::Entity::find()
        .expr_as(
            crate::db::crypto_expr::pgp_decrypt_expr(sea_orm::sea_query::Expr::col(
                keys::Column::PrivateKeyPemEnc,
            )),
            "private_key_pem",
        )
        .filter(keys::Column::ProviderId.eq(provider_id))
        .filter(keys::Column::Kid.eq(kid))
        .into_model::<crate::db::helper::signing_key::SigningKeyRow>()
        .one(&txn)
        .await?
        .ok_or(ManagementError::Invalid("not_found"))?;
    if key.key.revoked_at.is_some() || !currently_valid(key.key.not_before, key.key.expires_at) {
        return Err(ManagementError::Invalid("key_not_currently_valid"));
    }
    if key.key.algorithm != KeyAlgorithm::Rs256
        || key.key.r#use != KeyUse::Sig
        || key.private_key_pem.is_none()
    {
        return Err(ManagementError::Invalid("invalid_signing_key"));
    }
    pero_utils::oauth::jwk::validate_signing_key(
        &key.key.public_key_pem,
        key.private_key_pem.as_deref(),
    )
    .map_err(ManagementError::Validation)?;
    deactivate_signing_keys(&txn, provider_id).await?;
    let mut active: keys::ActiveModel = key.key.into();
    active.active = Set(true);
    active.updated_at = Set(OffsetDateTime::now_utc());
    active.update(&txn).await?;
    txn.commit().await?;
    Ok(())
}

pub async fn revoke(
    db: &DatabaseConnection,
    provider_id: Uuid,
    kid: &str,
) -> Result<(), ManagementError> {
    let txn = db.begin().await?;
    lock_provider(&txn, provider_id).await?;
    let key = keys::Entity::find()
        .filter(keys::Column::ProviderId.eq(provider_id))
        .filter(keys::Column::Kid.eq(kid))
        .one(&txn)
        .await?
        .ok_or(ManagementError::Invalid("not_found"))?;
    let now = OffsetDateTime::now_utc();
    let mut active: keys::ActiveModel = key.into();
    active.active = Set(false);
    active.revoked_at = Set(Some(now));
    active.updated_at = Set(now);
    active.update(&txn).await?;
    txn.commit().await?;
    Ok(())
}

async fn lock_provider<C: ConnectionTrait>(db: &C, id: Uuid) -> Result<(), ManagementError> {
    identity_providers::Entity::find_by_id(id)
        .lock_exclusive()
        .one(db)
        .await?
        .ok_or(ManagementError::Invalid("not_found"))?;
    Ok(())
}

async fn deactivate_signing_keys<C: ConnectionTrait>(
    db: &C,
    id: Uuid,
) -> Result<(), sea_orm::DbErr> {
    // Keep old public keys available for verification until they are revoked.
    keys::Entity::update_many()
        .col_expr(keys::Column::Active, sea_orm::sea_query::Expr::value(false))
        .col_expr(
            keys::Column::UpdatedAt,
            sea_orm::sea_query::Expr::value(OffsetDateTime::now_utc()),
        )
        .filter(keys::Column::ProviderId.eq(id))
        .filter(keys::Column::Use.eq(KeyUse::Sig))
        .filter(keys::Column::Active.eq(true))
        .exec(db)
        .await?;
    Ok(())
}
