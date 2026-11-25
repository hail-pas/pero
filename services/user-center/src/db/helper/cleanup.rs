use sea_orm::{
    ColumnTrait, ConnectionTrait, DatabaseConnection, DbBackend, EntityTrait, QueryFilter,
    QuerySelect, Statement, TransactionTrait,
};
use time::OffsetDateTime;

use crate::db::entity::{refresh_tokens, sso_sessions};
use sea_orm::QueryOrder;

const BATCH_SIZE: u64 = 500;
const MAX_BATCHES: usize = 20;

async fn execute_batches(db: &DatabaseConnection, sql: &str) -> Result<u64, sea_orm::DbErr> {
    let now = OffsetDateTime::now_utc();
    let mut total = 0;
    for _ in 0..MAX_BATCHES {
        let deleted = db
            .execute_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                sql,
                [now.into()],
            ))
            .await?
            .rows_affected();
        total += deleted;
        if deleted < BATCH_SIZE {
            break;
        }
        tokio::task::yield_now().await;
    }
    Ok(total)
}

async fn delete_before(
    db: &DatabaseConnection,
    table: &str,
    condition: &str,
    order_column: &str,
) -> Result<u64, sea_orm::DbErr> {
    // Identifiers and conditions are static literals supplied by the helpers below.
    let sql = format!(
        "DELETE FROM {table} WHERE id IN (SELECT id FROM {table} WHERE {condition} ORDER BY {order_column} LIMIT {BATCH_SIZE} FOR UPDATE SKIP LOCKED)"
    );
    execute_batches(db, &sql).await
}

async fn delete_expired(
    db: &DatabaseConnection,
    table: &str,
    condition: &str,
) -> Result<u64, sea_orm::DbErr> {
    delete_before(db, table, condition, "expires_at").await
}

macro_rules! clean_expired {
    ($fn_name:ident, $table:literal) => {
        pub async fn $fn_name(db: &DatabaseConnection) -> Result<u64, sea_orm::DbErr> {
            delete_expired(db, $table, "expires_at < $1").await
        }
    };
}
clean_expired!(
    clean_expired_authorization_requests,
    "authorization_requests"
);
clean_expired!(clean_expired_authorization_codes, "authorization_codes");

pub async fn clean_expired_sso_sessions(
    db: &DatabaseConnection,
    idle_ttl_seconds: u64,
) -> Result<u64, sea_orm::DbErr> {
    let mut total = 0;
    for _ in 0..MAX_BATCHES {
        let txn = db.begin().await?;
        let now = OffsetDateTime::now_utc();
        let ids: Vec<uuid::Uuid> = sso_sessions::Entity::find()
            .select_only()
            .column(sso_sessions::Column::Id)
            .filter(
                sea_orm::Condition::any()
                    .add(sso_sessions::Column::ExpiresAt.lte(now))
                    .add(sso_sessions::Column::LastSeenAt.lte(
                        now - time::Duration::seconds(idle_ttl_seconds as i64),
                    )),
            )
            .order_by_asc(sso_sessions::Column::ExpiresAt)
            .order_by_asc(sso_sessions::Column::Id)
            // Match token issuance and logout: lock sessions before refresh grants.
            .lock_exclusive()
            .limit(BATCH_SIZE)
            .into_tuple()
            .all(&txn)
            .await?;
        if ids.is_empty() {
            txn.commit().await?;
            break;
        }
        // Queue RP logout notifications through the existing revocation trigger
        // before deleting the session and its RP mappings.
        sso_sessions::Entity::update_many()
            .col_expr(
                sso_sessions::Column::RevokedAt,
                sea_orm::sea_query::Expr::value(Some(now)),
            )
            .col_expr(
                sso_sessions::Column::RevokeReason,
                sea_orm::sea_query::Expr::value("session_expired"),
            )
            .filter(sso_sessions::Column::Id.is_in(ids.clone()))
            .filter(sso_sessions::Column::RevokedAt.is_null())
            .exec(&txn)
            .await?;
        refresh_tokens::Entity::update_many()
            .col_expr(
                refresh_tokens::Column::RevokedAt,
                sea_orm::sea_query::Expr::value(Some(now)),
            )
            .col_expr(
                refresh_tokens::Column::RevokeReason,
                sea_orm::sea_query::Expr::value("session_expired"),
            )
            .filter(refresh_tokens::Column::SessionId.is_in(ids.clone()))
            .filter(refresh_tokens::Column::RevokedAt.is_null())
            .exec(&txn)
            .await?;
        let result = sso_sessions::Entity::delete_many()
            .filter(sso_sessions::Column::Id.is_in(ids))
            .exec(&txn)
            .await?;
        txn.commit().await?;
        total += result.rows_affected;
        if result.rows_affected < BATCH_SIZE {
            break;
        }
        tokio::task::yield_now().await;
    }
    // Orphans already fail authorization; revoke a bounded batch for bookkeeping.
    db.execute_raw(Statement::from_sql_and_values(DbBackend::Postgres,
        "UPDATE refresh_tokens SET revoked_at=$1, revoke_reason='session_expired' WHERE id IN (SELECT id FROM refresh_tokens WHERE session_id IS NULL AND revoked_at IS NULL LIMIT 500)", [OffsetDateTime::now_utc().into()])).await?;
    Ok(total)
}

clean_expired!(clean_expired_refresh_tokens, "refresh_tokens");
clean_expired!(
    clean_expired_contact_change_requests,
    "contact_change_requests"
);
pub async fn clean_expired_password_reset_tokens(
    db: &DatabaseConnection,
) -> Result<u64, sea_orm::DbErr> {
    delete_expired(
        db,
        "password_reset_tokens",
        "expires_at < $1 OR consumed_at < $1 - interval '1 day'",
    )
    .await
}

/// Keep credential expiry independent of gateway availability; retain only 30 days of terminal metadata.
pub async fn clean_notifications(db: &DatabaseConnection) -> Result<u64, sea_orm::DbErr> {
    let mut total = 0;
    for _ in 0..MAX_BATCHES {
        let expired = db.execute_raw(Statement::from_string(DbBackend::Postgres,
            "DELETE FROM notification_outbox WHERE id IN (SELECT id FROM notification_outbox WHERE expires_at<=now() ORDER BY expires_at FOR UPDATE SKIP LOCKED LIMIT 500)".to_owned())).await?.rows_affected();
        let archived = db.execute_raw(Statement::from_string(DbBackend::Postgres,
            "DELETE FROM notification_deliveries WHERE id IN (SELECT id FROM notification_deliveries WHERE updated_at<now()-interval '30 days' AND status IN ('delivered','expired','cancelled') ORDER BY updated_at LIMIT 500)".to_owned())).await?.rows_affected();
        total += expired + archived;
        if expired < BATCH_SIZE && archived < BATCH_SIZE {
            break;
        }
        tokio::task::yield_now().await;
    }
    Ok(total)
}

pub async fn clean_enrollments(db: &DatabaseConnection) -> Result<u64, sea_orm::DbErr> {
    let expired = execute_batches(
        db,
        "UPDATE enrollments SET status='expired' WHERE id IN (SELECT id FROM enrollments WHERE expires_at<=$1 AND status IN ('pending_verification','pending_approval','ready') ORDER BY expires_at LIMIT 500 FOR UPDATE SKIP LOCKED)",
    )
    .await?;
    let deleted = delete_expired(db, "enrollments", "expires_at < $1 - interval '30 days'").await?;
    Ok(expired + deleted)
}

pub async fn clean_tenant_invitations(db: &DatabaseConnection) -> Result<u64, sea_orm::DbErr> {
    let expired = execute_batches(
        db,
        "UPDATE tenant_invitations SET status='expired' WHERE id IN (SELECT id FROM tenant_invitations WHERE expires_at<=$1 AND status='pending' ORDER BY expires_at LIMIT 500 FOR UPDATE SKIP LOCKED)",
    )
    .await?;
    let deleted = delete_expired(
        db,
        "tenant_invitations",
        "expires_at < $1 - interval '30 days'",
    )
    .await?;
    Ok(expired + deleted)
}

async fn clean_delivery_history(
    db: &DatabaseConnection,
    table: &str,
    pending: &str,
) -> Result<u64, sea_orm::DbErr> {
    // Remove expired jobs from the hot queue indexes while retaining delivery history.
    // Do not invalidate a lease held by an in-flight delivery.
    let sql = format!(
        "UPDATE {table} SET expired_at=$1,lease_id=NULL,leased_until=NULL WHERE id IN (SELECT id FROM {table} WHERE {pending} AND expires_at<=$1 AND (leased_until IS NULL OR leased_until<=$1) ORDER BY expires_at LIMIT {BATCH_SIZE} FOR UPDATE SKIP LOCKED)"
    );
    let expired = execute_batches(db, &sql).await?;
    let deleted = delete_before(
        db,
        table,
        "created_at < $1 - interval '30 days'",
        "created_at",
    )
    .await?;
    Ok(expired + deleted)
}

pub async fn clean_backchannel_deliveries(db: &DatabaseConnection) -> Result<u64, sea_orm::DbErr> {
    clean_delivery_history(
        db,
        "backchannel_logout_deliveries",
        "delivered_at IS NULL AND expired_at IS NULL",
    )
    .await
}

pub async fn clean_account_sync_deliveries(db: &DatabaseConnection) -> Result<u64, sea_orm::DbErr> {
    clean_delivery_history(
        db,
        "account_sync_deliveries",
        "delivered_at IS NULL AND cancelled_at IS NULL AND expired_at IS NULL",
    )
    .await
}

pub async fn clean_expired_client_secrets(db: &DatabaseConnection) -> Result<u64, sea_orm::DbErr> {
    let mut total = 0;
    for _ in 0..MAX_BATCHES {
        let count=db.execute_raw(Statement::from_string(DbBackend::Postgres,"UPDATE oauth_clients SET previous_secret_hash=NULL,previous_secret_expires_at=NULL WHERE previous_secret_expires_at<=now() AND id IN (SELECT id FROM oauth_clients WHERE previous_secret_expires_at<=now() LIMIT 500 FOR UPDATE SKIP LOCKED)".to_owned())).await?.rows_affected();
        total += count;
        if count < BATCH_SIZE {
            break;
        }
        tokio::task::yield_now().await;
    }
    Ok(total)
}
