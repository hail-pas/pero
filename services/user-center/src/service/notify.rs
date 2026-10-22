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
    let payload = serde_json::to_string(message)
        .map_err(|_| DbErr::Custom("notification serialization failed".into()))?;
    // The same database encryption key protects provider secrets and queued credentials.
    db.execute_raw(Statement::from_sql_and_values(DbBackend::Postgres,
        "INSERT INTO notification_outbox (id, payload_enc, expires_at, user_id, kind) VALUES ($1, pgp_sym_encrypt($2, current_setting('app.encrypt_key')), $3, $4, $5)",
        [Uuid::now_v7().into(), payload.into(), expires_at.into(), user_id.into(), message.kind.into()])).await?;
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
        "UPDATE notification_outbox SET lease_id = $2, leased_until = now() + interval '120 seconds' WHERE id = $1",
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
    match result {
        Ok(Ok(response)) if response.status.is_success() => {
            let deleted = state
                .db
                .execute_raw(Statement::from_sql_and_values(
                    DbBackend::Postgres,
                    "DELETE FROM notification_outbox WHERE id = $1 AND lease_id = $2",
                    [delivery.id.into(), lease_id.into()],
                ))
                .await?
                .rows_affected();
            tracing::debug!(delivery_id = %delivery.id, elapsed_ms = started.elapsed().as_millis() as u64, lease_lost = deleted == 0, "Notification delivered");
        }
        _ => {
            // Do not log gateway bodies, URLs or credential-bearing payloads.
            tracing::warn!(delivery_id = %delivery.id, "Notification delivery failed; retry scheduled");
            let updated = state.db.execute_raw(Statement::from_sql_and_values(DbBackend::Postgres,
                "UPDATE notification_outbox SET attempts = attempts + 1, next_attempt_at = now() + interval '30 seconds' * LEAST(attempts + 1, 10), lease_id = NULL, leased_until = NULL WHERE id = $1 AND lease_id = $2", [delivery.id.into(), lease_id.into()])).await?.rows_affected();
            tracing::debug!(delivery_id = %delivery.id, elapsed_ms = started.elapsed().as_millis() as u64, lease_lost = updated == 0, "Notification retry recorded");
        }
    }
    Ok(true)
}

pub fn start_delivery_task(state: AppState) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(5));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tick.tick().await;
            if state.config.notification.endpoint.is_empty() {
                continue;
            }
            deliver_batch(&state).await;
        }
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
