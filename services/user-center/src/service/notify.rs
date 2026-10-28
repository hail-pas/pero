//! Durable delivery via an authenticated HTTPS notification gateway.
use pero_http_client_core::HttpClientExt;
use sea_orm::{ConnectionTrait, DbBackend, DbErr, FromQueryResult, Statement, TransactionTrait};
use serde::Serialize;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::state::app::AppState;

#[derive(Serialize)]
pub struct Notification<'a> {
    pub channel: &'a str,
    pub kind: &'a str,
    pub to: &'a str,
    pub code: Option<&'a str>,
    pub link: &'a str,
}

pub async fn enqueue<C: ConnectionTrait>(
    db: &C,
    user_id: Uuid,
    message: &Notification<'_>,
    expires_at: OffsetDateTime,
) -> Result<(), DbErr> {
    enqueue_owned(db, Some(user_id), None, message, expires_at).await
}

pub async fn enqueue_enrollment<C: ConnectionTrait>(
    db: &C,
    enrollment_id: Uuid,
    message: &Notification<'_>,
    expires_at: OffsetDateTime,
) -> Result<(), DbErr> {
    enqueue_owned(db, None, Some(enrollment_id), message, expires_at).await
}

async fn enqueue_owned<C: ConnectionTrait>(
    db: &C,
    user_id: Option<Uuid>,
    enrollment_id: Option<Uuid>,
    message: &Notification<'_>,
    expires_at: OffsetDateTime,
) -> Result<(), DbErr> {
    let payload = serde_json::to_string(message)
        .map_err(|_| DbErr::Custom("notification serialization failed".into()))?;
    let recipient = match message.channel {
        "email" => super::contact::ContactChannel::Email.mask(message.to),
        "phone" => super::contact::ContactChannel::Phone.mask(message.to),
        _ => "***".into(),
    };
    // Queue and metadata are atomic even for callers without an explicit transaction.
    db.execute_raw(Statement::from_sql_and_values(DbBackend::Postgres,
        "WITH queued AS (INSERT INTO notification_outbox(id,payload_enc,expires_at,user_id,enrollment_id,kind) VALUES($1,pgp_sym_encrypt($2,current_setting('app.encrypt_key')),$3,$4,$5,$6) RETURNING id) INSERT INTO notification_deliveries(id,user_id,enrollment_id,kind,channel,recipient) SELECT id,$4,$5,$6,$7,$8 FROM queued",
        [Uuid::now_v7().into(),payload.into(),expires_at.into(),user_id.into(),enrollment_id.into(),message.kind.into(),message.channel.into(),recipient.into()])).await?;
    Ok(())
}

pub async fn retry(state: &AppState, id: Uuid) -> Result<(), super::ManagementError> {
    if state.config.notification.endpoint.is_empty() {
        return Err(super::ManagementError::Invalid("notification_disabled"));
    }
    let updated = state.db.execute_raw(Statement::from_sql_and_values(DbBackend::Postgres,
        "UPDATE notification_outbox SET next_attempt_at=now() WHERE id=$1 AND attempts>0 AND expires_at>now() AND next_attempt_at>now() AND (leased_until IS NULL OR leased_until<=now())",
        [id.into()])).await?.rows_affected();
    if updated == 0 {
        return Err(super::ManagementError::Invalid(
            "notification_not_retryable",
        ));
    }
    Ok(())
}

pub async fn enqueue_verification<C: ConnectionTrait>(
    db: &C,
    user_id: Uuid,
    base_url: &str,
    channel: &str,
    to: &str,
    code: &str,
    nonce: &str,
) -> Result<(), DbErr> {
    let mut link =
        pero_utils::oauth::url::issuer_endpoint(base_url, "account/profile/verify-contact");
    pero_utils::encode::append_query_param(&mut link, "nonce", nonce);
    enqueue(
        db,
        user_id,
        &Notification {
            channel,
            kind: "verify_contact",
            to,
            code: Some(code),
            link: &link,
        },
        OffsetDateTime::now_utc() + time::Duration::minutes(15),
    )
    .await
}

#[derive(FromQueryResult)]
struct Delivery {
    id: Uuid,
    payload: String,
}

pub(crate) async fn deliver_one(state: &AppState) -> Result<bool, DbErr> {
    let txn = state.db.begin().await?;
    let expired = txn.execute_raw(Statement::from_string(
        DbBackend::Postgres,
        "DELETE FROM notification_outbox WHERE id IN (SELECT id FROM notification_outbox WHERE expires_at <= now() ORDER BY expires_at FOR UPDATE SKIP LOCKED LIMIT 500)".to_owned(),
    )).await?.rows_affected();
    tracing::debug!(expired, "Expired notifications removed");
    let delivery = Delivery::find_by_statement(Statement::from_string(DbBackend::Postgres,
        "SELECT id, pgp_sym_decrypt(payload_enc, current_setting('app.encrypt_key')) AS payload FROM notification_outbox WHERE next_attempt_at <= now() AND expires_at > now() AND (leased_until IS NULL OR leased_until <= now()) ORDER BY next_attempt_at FOR UPDATE SKIP LOCKED LIMIT 1".to_owned()))
        .one(&txn).await?;
    let Some(delivery) = delivery else {
        txn.commit().await?;
        return Ok(false);
    };
    let lease_id = Uuid::now_v7();
    txn.execute_raw(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "WITH claimed AS (UPDATE notification_outbox SET lease_id = $2, leased_until = now() + interval '120 seconds', attempts = attempts + 1 WHERE id = $1 RETURNING id,attempts) UPDATE notification_deliveries d SET attempts=c.attempts,updated_at=now() FROM claimed c WHERE d.id=c.id",
        [delivery.id.into(), lease_id.into()],
    )).await?;
    txn.commit().await?;
    let config = &state.config.notification;
    let request = state
        .http_client
        .post(&config.endpoint)
        .bearer_auth(config.bearer_token.expose_secret())
        .header(
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("application/json"),
        )
        .header(
            http::HeaderName::from_static("idempotency-key"),
            http::HeaderValue::from_str(&delivery.id.to_string()).expect("UUID header"),
        )
        .body(delivery.payload.into_bytes())
        .send();
    // Bound delivery below the lease duration even if the configured HTTP timeout is longer.
    let started = std::time::Instant::now();
    let result = tokio::time::timeout(std::time::Duration::from_secs(60), request).await;
    // Store only a controlled error category and HTTP status, never gateway response content.
    let (error, status) = match result {
        Ok(Ok(response)) if response.status.is_success() => {
            (None, Some(i32::from(response.status.as_u16())))
        }
        Ok(Ok(response)) => (
            Some("http_error"),
            Some(i32::from(response.status.as_u16())),
        ),
        Ok(Err(error)) => {
            let status = error
                .extensions()
                .get("upstream_status")
                .and_then(serde_json::Value::as_u64)
                .and_then(|v| i32::try_from(v).ok());
            if status.is_some() {
                (Some("http_error"), status)
            } else if error.kind() == pero_error::ErrorKind::Timeout {
                (Some("timeout"), None)
            } else {
                (Some("transport_error"), None)
            }
        }
        Err(_) => (Some("timeout"), None),
    };
    let txn = state.db.begin().await?;
    // Lock the leased message before changing metadata; cancellation and stale workers cannot revive it.
    let owned = txn
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT id FROM notification_outbox WHERE id=$1 AND lease_id=$2 FOR UPDATE",
            [delivery.id.into(), lease_id.into()],
        ))
        .await?
        .is_some();
    if owned {
        txn.execute_raw(Statement::from_sql_and_values(DbBackend::Postgres,
            "UPDATE notification_deliveries SET status=$2,last_error=$3,http_status=$4,updated_at=now() WHERE id=$1",
            [delivery.id.into(),if error.is_none() { "delivered" } else { "retrying" }.into(),error.map(str::to_owned).into(),status.into()])).await?;
        if error.is_none() {
            txn.execute_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "DELETE FROM notification_outbox WHERE id=$1",
                [delivery.id.into()],
            ))
            .await?;
        } else {
            txn.execute_raw(Statement::from_sql_and_values(DbBackend::Postgres,
                "UPDATE notification_outbox SET next_attempt_at=now()+interval '30 seconds'*LEAST(attempts,10),lease_id=NULL,leased_until=NULL WHERE id=$1",
                [delivery.id.into()])).await?;
            tracing::warn!(delivery_id = %delivery.id, error, http_status = status, "Notification delivery failed; retry scheduled");
        }
    }
    txn.commit().await?;
    tracing::debug!(delivery_id = %delivery.id, elapsed_ms = started.elapsed().as_millis() as u64, lease_lost = !owned, "Notification attempt completed");
    Ok(true)
}

async fn warn_backlog(db: &sea_orm::DatabaseConnection) -> Result<(), DbErr> {
    if let Some(row) = db.query_one_raw(Statement::from_string(DbBackend::Postgres,
        "SELECT count(*) AS pending,count(*) FILTER (WHERE (attempts>=3 AND leased_until IS NULL) OR next_attempt_at<now()-interval '5 minutes') AS unhealthy FROM notification_outbox WHERE expires_at>now()".to_owned())).await? {
        let unhealthy: i64 = row.try_get("", "unhealthy")?;
        let pending: i64 = row.try_get("", "pending")?;
        if unhealthy > 0 {
            tracing::warn!(pending, unhealthy, "Notification backlog requires attention");
        }
    }
    Ok(())
}

pub fn start_delivery_task(state: AppState) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let delivery = async {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(5));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tick.tick().await;
                if !state.config.notification.endpoint.is_empty() {
                    deliver_batch(&state).await;
                }
            }
        };
        // Check independently of slow gateway requests and the hourly cleanup task.
        // Keep monitoring when delivery is disabled so queued security notices remain visible.
        let monitor = async {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tick.tick().await;
                if let Err(error) = warn_backlog(&state.db).await {
                    tracing::error!(%error, "Notification backlog check failed");
                }
            }
        };
        tokio::join!(delivery, monitor);
    })
}

pub(crate) async fn deliver_batch(state: &AppState) {
    // Keep the existing 20-attempt batch bound while isolating slow deliveries.
    // Dropping JoinSet on shutdown also aborts its workers; leases allow recovery.
    let mut workers = tokio::task::JoinSet::new();
    for _ in 0..4 {
        let state = state.clone();
        workers.spawn(async move {
            for _ in 0..5 {
                match deliver_one(&state).await {
                    Ok(true) => {}
                    Ok(false) => break,
                    Err(_) => {
                        tracing::error!("Notification queue unavailable");
                        break;
                    }
                }
            }
        });
    }
    while let Some(result) = workers.join_next().await {
        if let Err(error) = result {
            tracing::error!(%error, "Notification worker stopped unexpectedly");
        }
    }
}
