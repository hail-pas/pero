use sea_orm::{
    ColumnTrait, ConnectionTrait, DatabaseConnection, DbBackend, EntityTrait, QueryFilter,
    QuerySelect, Statement, TransactionTrait,
};
use time::OffsetDateTime;

use crate::db::entity::{refresh_tokens, sso_sessions};
use sea_orm::QueryOrder;

const BATCH_SIZE: u64 = 500;
const MAX_BATCHES: usize = 20;

async fn delete_expired(
    db: &DatabaseConnection,
    table: &str,
    condition: &str,
) -> Result<u64, sea_orm::DbErr> {
    // Identifiers/conditions are static literals supplied only by the helpers below.
    let sql = format!(
        "DELETE FROM {table} WHERE id IN (SELECT id FROM {table} WHERE {condition} ORDER BY expires_at LIMIT {BATCH_SIZE})"
    );
    let now = OffsetDateTime::now_utc();
    let mut total = 0;
    for _ in 0..MAX_BATCHES {
        let deleted = db
            .execute_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                &sql,
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
clean_expired!(
    clean_expired_external_login_requests,
    "external_login_requests"
);

pub async fn clean_expired_sso_sessions(db: &DatabaseConnection) -> Result<u64, sea_orm::DbErr> {
    let mut total = 0;
    for _ in 0..MAX_BATCHES {
        let txn = db.begin().await?;
        let now = OffsetDateTime::now_utc();
        let ids: Vec<uuid::Uuid> = sso_sessions::Entity::find()
            .select_only()
            .column(sso_sessions::Column::Id)
            .filter(sso_sessions::Column::ExpiresAt.lt(now))
            .order_by_asc(sso_sessions::Column::ExpiresAt)
            .limit(BATCH_SIZE)
            .into_tuple()
            .all(&txn)
            .await?;
        if ids.is_empty() {
            txn.commit().await?;
            break;
        }
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
