use sea_orm::{ConnectionTrait, DatabaseConnection, DbBackend, Statement};
use time::OffsetDateTime;

const BATCH_SIZE: u64 = 500;
const MAX_BATCHES: usize = 20;
pub(crate) const CLEANUP_PASS_LIMIT: u64 = BATCH_SIZE * MAX_BATCHES as u64;

async fn execute_batches(db: &DatabaseConnection, sql: &str) -> Result<u64, sea_orm::DbErr> {
    execute_batches_at(db, sql, OffsetDateTime::now_utc()).await
}

async fn execute_batches_at(
    db: &DatabaseConnection,
    sql: &str,
    cutoff: OffsetDateTime,
) -> Result<u64, sea_orm::DbErr> {
    let mut total = 0;
    for _ in 0..MAX_BATCHES {
        let deleted = db
            .execute_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                sql,
                [cutoff.into()],
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
    cutoff: OffsetDateTime,
) -> Result<u64, sea_orm::DbErr> {
    let sql = delete_batch_sql(table, condition, order_column);
    execute_batches_at(db, &sql, cutoff).await
}

fn delete_batch_sql(table: &str, condition: &str, order_column: &str) -> String {
    // Identifiers and conditions are static literals supplied by the helpers below.
    // The row locks keep these tuple IDs valid for the duration of the statement.
    format!(
        "DELETE FROM ONLY {table} WHERE ctid = ANY (ARRAY(
            SELECT ctid FROM ONLY {table} WHERE {condition}
            ORDER BY {order_column} LIMIT {BATCH_SIZE} FOR UPDATE SKIP LOCKED
        ))"
    )
}

async fn delete_expired(
    db: &DatabaseConnection,
    table: &str,
    condition: &str,
) -> Result<u64, sea_orm::DbErr> {
    delete_before(
        db,
        table,
        condition,
        "expires_at",
        OffsetDateTime::now_utc(),
    )
    .await
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
    let now = OffsetDateTime::now_utc();
    // Sweep each lifetime independently so both use an ordered index range scan.
    // The delete trigger queues RP logout before the cascade removes sessions and grants.
    let absolute = delete_before(
        db,
        "sso_sessions",
        "expires_at <= $1",
        "expires_at, id",
        now,
    )
    .await?;
    let idle = delete_before(
        db,
        "sso_sessions",
        "last_seen_at <= $1",
        "last_seen_at, id",
        now - time::Duration::seconds(idle_ttl_seconds as i64),
    )
    .await?;

    Ok(absolute + idle)
}

clean_expired!(clean_expired_refresh_tokens, "refresh_tokens");
clean_expired!(
    clean_expired_contact_change_requests,
    "contact_change_requests"
);
pub async fn clean_expired_password_reset_tokens(
    db: &DatabaseConnection,
) -> Result<u64, sea_orm::DbErr> {
    let now = OffsetDateTime::now_utc();
    let expired = delete_before(
        db,
        "password_reset_tokens",
        "expires_at < $1",
        "expires_at",
        now,
    )
    .await?;
    let consumed = delete_before(
        db,
        "password_reset_tokens",
        "consumed_at < $1",
        "consumed_at",
        now - time::Duration::days(1),
    )
    .await?;
    Ok(expired + consumed)
}

/// Remove abandoned MFA setups and expired recovery credentials under the same
/// user lock used by factor enrollment and verification.
pub async fn clean_expired_mfa(db: &DatabaseConnection) -> Result<u64, sea_orm::DbErr> {
    let deleted = execute_batches(
        db,
        "DELETE FROM user_mfa f WHERE NOT f.enabled AND f.setup_expires_at <= $1
         AND f.user_id IN (SELECT u.id FROM user_mfa m JOIN users u ON u.id=m.user_id
             WHERE NOT m.enabled AND m.setup_expires_at <= $1 ORDER BY m.setup_expires_at
             LIMIT 500 FOR UPDATE OF u SKIP LOCKED)",
    )
    .await?;
    let abandoned_setups = execute_batches(
        db,
        "UPDATE user_mfa f SET pending_secret_enc=NULL,setup_session=NULL
         WHERE f.enabled AND f.pending_secret_enc IS NOT NULL AND f.setup_expires_at <= $1
         AND f.user_id IN (SELECT u.id FROM user_mfa m JOIN users u ON u.id=m.user_id
             WHERE m.enabled AND m.pending_secret_enc IS NOT NULL AND m.setup_expires_at <= $1
             ORDER BY m.setup_expires_at LIMIT 500 FOR UPDATE OF u SKIP LOCKED)",
    )
    .await?;
    let expired_recoveries = execute_batches(
        db,
        "UPDATE user_mfa f SET assisted_recovery_hash=NULL,assisted_recovery_expires_at=NULL
         WHERE f.enabled AND f.assisted_recovery_expires_at <= $1
         AND f.user_id IN (SELECT u.id FROM user_mfa m JOIN users u ON u.id=m.user_id
             WHERE m.enabled AND m.assisted_recovery_expires_at <= $1
             ORDER BY m.assisted_recovery_expires_at LIMIT 500 FOR UPDATE OF u SKIP LOCKED)",
    )
    .await?;
    Ok(deleted + abandoned_setups + expired_recoveries)
}

async fn clean_event_history(
    db: &DatabaseConnection,
    table: &str,
    days: u16,
) -> Result<u64, sea_orm::DbErr> {
    if days == 0 {
        return Ok(0);
    }
    let cutoff = OffsetDateTime::now_utc() - time::Duration::days(i64::from(days));
    delete_before(db, table, "created_at < $1", "created_at", cutoff).await
}

pub async fn clean_login_events(db: &DatabaseConnection, days: u16) -> Result<u64, sea_orm::DbErr> {
    clean_event_history(db, "login_events", days).await
}

/// Retain unbound identities for the login history window and while referenced.
pub async fn clean_unbound_identities(
    db: &DatabaseConnection,
    days: u16,
) -> Result<u64, sea_orm::DbErr> {
    if days == 0 {
        return Ok(0);
    }
    let cutoff = OffsetDateTime::now_utc() - time::Duration::days(i64::from(days));
    delete_before(
        db,
        "identities",
        "unbound_at < $1 AND NOT EXISTS (SELECT 1 FROM login_events e WHERE e.identity_id=identities.id) AND NOT EXISTS (SELECT 1 FROM sso_sessions s WHERE s.identity_id=identities.id)",
        "unbound_at",
        cutoff,
    )
    .await
}

pub async fn clean_audit_events(db: &DatabaseConnection, days: u16) -> Result<u64, sea_orm::DbErr> {
    clean_event_history(db, "audit_events", days).await
}

pub(crate) async fn clean_expired_notification_batch(
    db: &DatabaseConnection,
) -> Result<u64, sea_orm::DbErr> {
    let sql = delete_batch_sql(
        "notification_outbox",
        "expires_at <= now() AND (leased_until IS NULL OR leased_until <= now())",
        "expires_at",
    );
    Ok(db
        .execute_raw(Statement::from_string(DbBackend::Postgres, sql))
        .await?
        .rows_affected())
}

/// Keep credential expiry independent of gateway availability; retain only 30 days of terminal metadata.
pub async fn clean_notifications(db: &DatabaseConnection) -> Result<u64, sea_orm::DbErr> {
    let mut expired = 0;
    for _ in 0..MAX_BATCHES {
        let removed = clean_expired_notification_batch(db).await?;
        expired += removed;
        if removed < BATCH_SIZE {
            break;
        }
        tokio::task::yield_now().await;
    }
    let archived = delete_before(
        db,
        "notification_deliveries",
        "updated_at < $1 AND status IN ('delivered','expired','cancelled')",
        "updated_at",
        OffsetDateTime::now_utc() - time::Duration::days(30),
    )
    .await?;
    Ok(expired + archived)
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
        OffsetDateTime::now_utc(),
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
    execute_batches(
        db,
        "UPDATE oauth_clients SET previous_secret_hash=NULL,previous_secret_expires_at=NULL
         WHERE id IN (SELECT id FROM oauth_clients WHERE previous_secret_expires_at<=LEAST($1,now())
             ORDER BY previous_secret_expires_at LIMIT 500 FOR UPDATE SKIP LOCKED)",
    )
    .await
}

pub async fn clean_expired_signing_key_material(
    db: &DatabaseConnection,
) -> Result<u64, sea_orm::DbErr> {
    // Previously issued tokens may still need the public key for verification.
    execute_batches(
        db,
        "UPDATE identity_provider_keys SET private_key_pem_enc=NULL,activate_at=NULL,updated_at=now()
         WHERE id IN (SELECT id FROM identity_provider_keys WHERE expires_at<=LEAST($1,now())
             AND (private_key_pem_enc IS NOT NULL OR activate_at IS NOT NULL)
             ORDER BY expires_at LIMIT 500 FOR UPDATE SKIP LOCKED)",
    )
    .await
}
