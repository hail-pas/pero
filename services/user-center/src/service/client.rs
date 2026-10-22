//! Commit client policy changes and grant revocation as one operation.
use crate::db::entity::oauth_clients;
use sea_orm::{
    ActiveModelTrait, DatabaseConnection, DbErr, EntityTrait, QuerySelect, TransactionTrait,
};

pub async fn save_security_change(
    db: &DatabaseConnection,
    expected: &oauth_clients::Model,
    active: oauth_clients::ActiveModel,
    revoke_reason: Option<&str>,
) -> Result<(), DbErr> {
    let txn = db.begin().await?;
    let current = oauth_clients::Entity::find_by_id(expected.id)
        .lock_exclusive()
        .one(&txn)
        .await?;
    // The handler may spend time hashing a secret. Never overwrite a concurrent policy edit.
    if current.as_ref() != Some(expected) {
        return Err(DbErr::Custom(
            "Client policy changed; reload and retry".into(),
        ));
    }
    let updated = active.update(&txn).await?;
    if let Some(reason) = revoke_reason {
        super::session::SessionService::revoke_client_grants(&txn, updated.id, reason).await?;
    }
    txn.commit().await
}
