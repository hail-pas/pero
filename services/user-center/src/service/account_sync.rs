//! Transactional account change notifications; receivers fetch current, app-scoped state.
use crate::state::app::AppState;
use sea_orm::{ConnectionTrait, DbBackend, DbErr, FromQueryResult, Statement};
use uuid::Uuid;

#[derive(FromQueryResult)]
struct Delivery {
    id: Uuid,
    user_id: Uuid,
    kind: String,
    endpoint: String,
    identifier: String,
    created_at: time::OffsetDateTime,
}

pub(crate) async fn deliver_one(state: &AppState) -> Result<bool, DbErr> {
    let lease = Uuid::now_v7();
    let job = Delivery::find_by_statement(Statement::from_sql_and_values(DbBackend::Postgres,
        "WITH candidate AS (SELECT d.id FROM account_sync_deliveries d JOIN oauth_clients c ON c.id=d.client_id WHERE d.delivered_at IS NULL AND d.cancelled_at IS NULL AND d.expires_at>now() AND d.next_attempt_at<=now() AND (d.leased_until IS NULL OR d.leased_until<=now()) AND c.status='active' AND c.account_sync_uri=d.endpoint ORDER BY d.next_attempt_at FOR UPDATE OF d SKIP LOCKED LIMIT 1), claimed AS (UPDATE account_sync_deliveries SET lease_id=$1,leased_until=now()+interval '120 seconds',attempts=attempts+1 WHERE id=(SELECT id FROM candidate) RETURNING *) SELECT d.id,d.user_id,d.kind,d.endpoint,d.created_at,c.identifier::text FROM claimed d JOIN oauth_clients c ON c.id=d.client_id",
        [lease.into()])).one(&state.db).await?;
    let Some(job) = job else {
        return Ok(false);
    };
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let claims = serde_json::json!({
        "iss": state.config.oidc.issuer, "aud": job.identifier,
        "sub": job.user_id, "iat": now, "exp": now+120, "jti": job.id,
        "event": job.kind, "occurred_at": job.created_at.unix_timestamp(),
    });
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(60),
        super::backchannel::send_signed(
            state,
            &job.endpoint,
            "pero-account-sync+jwt",
            "event_token",
            &claims,
        ),
    )
    .await;
    let error = match result {
        Ok(Ok(())) => None,
        Ok(Err(error)) => Some(error),
        Err(_) => Some("timeout"),
    };
    state.db.execute_raw(Statement::from_sql_and_values(DbBackend::Postgres,
        "UPDATE account_sync_deliveries SET delivered_at=CASE WHEN $3::text IS NULL THEN now() ELSE NULL END,last_error=$3,next_attempt_at=now()+interval '30 seconds'*LEAST(attempts,120),leased_until=NULL,lease_id=NULL WHERE id=$1 AND lease_id=$2",
        [job.id.into(),lease.into(),error.into()])).await?;
    if let Some(error) = error {
        tracing::warn!(delivery_id=%job.id,error,"Account synchronization failed; retry scheduled");
    }
    Ok(true)
}

pub fn start(state: AppState) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(5));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tick.tick().await;
            for _ in 0..20 {
                match deliver_one(&state).await {
                    Ok(true) => {}
                    Ok(false) => break,
                    Err(error) => {
                        tracing::error!(%error,"Account synchronization queue unavailable");
                        break;
                    }
                }
            }
        }
    })
}

/// One query observes account, membership and client field policy in the same snapshot.
pub async fn snapshot(
    db: &sea_orm::DatabaseConnection,
    client: Uuid,
    user: Uuid,
) -> Result<Option<serde_json::Value>, DbErr> {
    let row = db.query_one_raw(Statement::from_sql_and_values(DbBackend::Postgres,
        "SELECT u.id,u.username::text,u.email::text,u.email_verified_at,u.phone::text,u.phone_verified_at,u.nickname,u.avatar_url,u.status,u.created_at,u.updated_at,u.deleted_at,a.status::text AS membership_status,app.status='active' AS app_active,c.scopes FROM users u JOIN user_app_access a ON a.user_id=u.id JOIN apps app ON app.id=a.app_id JOIN oauth_clients c ON c.app_id=a.app_id WHERE u.id=$2 AND c.id=$1 AND c.status='active' AND c.type='confidential' AND c.account_sync_uri IS NOT NULL AND NOT app.system",
        [client.into(),user.into()])).await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let user = crate::db::entity::users::Model::from_query_result(&row, "")?;
    let membership: String = row.try_get("", "membership_status")?;
    let active = user.deleted_at.is_none()
        && user.status == crate::db::enums::UserStatus::Active
        && membership == "active"
        && row.try_get::<bool>("", "app_active")?;
    let profile = if active {
        serde_json::to_value(super::scope::user_claims(
            &user,
            &row.try_get::<Vec<String>>("", "scopes")?,
        ))
        .expect("user claims contain only JSON primitives")
    } else {
        serde_json::json!({})
    };
    Ok(Some(serde_json::json!({
        "sub": user.id, "active": active,
        "account_status": if user.deleted_at.is_some() { "deleted".to_owned() } else { user.status.to_string() },
        "membership_status": membership, "profile": profile,
    })))
}
