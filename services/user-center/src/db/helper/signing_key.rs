use sea_orm::{
    ColumnTrait, ConnectionTrait, DbErr, EntityTrait, ExprTrait, FromQueryResult, QueryFilter,
    QuerySelect, sea_query::Expr,
};

use super::identity_provider::find_local_provider;
use crate::db::crypto_expr::pgp_decrypt_expr;
use crate::db::entity::identity_provider_keys as ipk;
use crate::db::enums::{KeyAlgorithm, KeyUse};

#[derive(Clone, FromQueryResult)]
pub struct SigningKeyRow {
    #[sea_orm(nested)]
    pub key: ipk::Model,

    #[sea_orm(from_alias = "private_key_pem")]
    pub private_key_pem: Option<String>,
}

#[derive(Clone)]
pub struct SigningKeyMaterial {
    pub kid: String,
    pub private_key: String,
}

pub fn apply_signing_key_filter<S>(query: S) -> S
where
    S: sea_orm::QueryFilter,
{
    let now = time::OffsetDateTime::now_utc();
    query
        .filter(ipk::Column::RevokedAt.is_null())
        .filter(
            ipk::Column::ExpiresAt
                .is_null()
                .or(ipk::Column::ExpiresAt.gt(now)),
        )
        .filter(
            ipk::Column::NotBefore
                .is_null()
                .or(ipk::Column::NotBefore.lte(now)),
        )
}

pub fn apply_verification_key_filter<S>(query: S) -> S
where
    S: sea_orm::QueryFilter,
{
    let now = time::OffsetDateTime::now_utc();
    query.filter(ipk::Column::RevokedAt.is_null()).filter(
        ipk::Column::NotBefore
            .is_null()
            .or(ipk::Column::NotBefore.lte(now)),
    )
}

pub async fn find_active_signing_key<C>(db: &C) -> Result<Option<SigningKeyRow>, DbErr>
where
    C: ConnectionTrait,
{
    let provider = find_local_provider(db).await?;

    apply_signing_key_filter(
        ipk::Entity::find()
            .expr_as(
                pgp_decrypt_expr(Expr::col(ipk::Column::PrivateKeyPemEnc)),
                "private_key_pem",
            )
            .filter(ipk::Column::ProviderId.eq(provider.id))
            .filter(ipk::Column::Active.eq(true))
            .filter(ipk::Column::Use.eq(KeyUse::Sig))
            .filter(ipk::Column::Algorithm.eq(KeyAlgorithm::Rs256)),
    )
    .lock_exclusive()
    .into_model::<SigningKeyRow>()
    .one(db)
    .await
}

pub async fn require_active_signing_key<C>(db: &C) -> Result<SigningKeyMaterial, DbErr>
where
    C: ConnectionTrait,
{
    let row = find_active_signing_key(db)
        .await?
        .ok_or_else(|| DbErr::Custom("no active signing key".into()))?;
    let private_key = row
        .private_key_pem
        .ok_or_else(|| DbErr::Custom("private key decrypt returned null".into()))?;
    // Issuance holds this row lock until commit; rotation/revocation cannot race it.
    // Include ID/access-token lifetime, logout-token lifetime and clock skew.
    db.execute_raw(sea_orm::Statement::from_sql_and_values(sea_orm::DbBackend::Postgres,
        "UPDATE identity_provider_keys SET last_issued_until=GREATEST(last_issued_until,now()+make_interval(secs=>GREATEST(120,COALESCE((SELECT max(GREATEST(access_token_ttl_seconds,id_token_ttl_seconds)) FROM oauth_clients),0))+300)) WHERE id=$1",
        [row.key.id.into()])).await?;
    Ok(SigningKeyMaterial {
        kid: row.key.kid,
        private_key,
    })
}

pub async fn find_verification_key_by_kid<C>(db: &C, kid: &str) -> Result<Option<ipk::Model>, DbErr>
where
    C: ConnectionTrait,
{
    let provider = find_local_provider(db).await?;

    apply_verification_key_filter(
        ipk::Entity::find()
            .filter(ipk::Column::ProviderId.eq(provider.id))
            .filter(ipk::Column::Kid.eq(kid))
            .filter(ipk::Column::Use.eq(KeyUse::Sig))
            .filter(ipk::Column::Algorithm.eq(KeyAlgorithm::Rs256)),
    )
    .one(db)
    .await
}
