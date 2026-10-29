//! Transactional RP session tracking and at-least-once OIDC logout delivery.
use crate::state::app::AppState;
use pero_http_client_core::HttpClientExt;
use sea_orm::{ConnectionTrait, DbBackend, DbErr, FromQueryResult, Statement, TransactionTrait};
use uuid::Uuid;

pub async fn remember<C: ConnectionTrait>(
    db: &C,
    session: Uuid,
    client: Uuid,
    user: Uuid,
) -> Result<(), DbErr> {
    db.execute_raw(Statement::from_sql_and_values(DbBackend::Postgres,
        "INSERT INTO oidc_rp_sessions(session_id,client_id,user_id) VALUES($1,$2,$3) ON CONFLICT DO NOTHING",
        [session.into(),client.into(),user.into()])).await?;
    Ok(())
}
#[derive(FromQueryResult)]
struct Delivery {
    id: Uuid,
    session_id: Uuid,
    user_id: Uuid,
    endpoint: String,
    identifier: String,
}
pub(crate) async fn deliver_one(state: &AppState) -> Result<bool, DbErr> {
    let lease = Uuid::now_v7();
    let job=Delivery::find_by_statement(Statement::from_sql_and_values(DbBackend::Postgres,
        "WITH claimed AS (UPDATE backchannel_logout_deliveries SET lease_id=$1,leased_until=now()+interval '120 seconds',attempts=attempts+1 WHERE id=(SELECT id FROM backchannel_logout_deliveries WHERE delivered_at IS NULL AND expires_at>now() AND next_attempt_at<=now() AND (leased_until IS NULL OR leased_until<=now()) ORDER BY next_attempt_at FOR UPDATE SKIP LOCKED LIMIT 1) RETURNING *) SELECT d.id,d.session_id,d.user_id,d.endpoint,c.identifier::text FROM claimed d JOIN oauth_clients c ON c.id=d.client_id",[lease.into()])).one(&state.db).await?;
    let Some(job) = job else {
        return Ok(false);
    };
    let result = tokio::time::timeout(std::time::Duration::from_secs(60), send(state, &job)).await;
    let error = match result {
        Ok(Ok(())) => None,
        Ok(Err(error)) => Some(error),
        Err(_) => Some("timeout"),
    };
    state.db.execute_raw(Statement::from_sql_and_values(DbBackend::Postgres,
        "UPDATE backchannel_logout_deliveries SET delivered_at=CASE WHEN $3::text IS NULL THEN now() ELSE NULL END,last_error=$3,next_attempt_at=now()+interval '30 seconds'*LEAST(attempts,120),leased_until=NULL,lease_id=NULL WHERE id=$1 AND lease_id=$2",
        [job.id.into(),lease.into(),error.into()])).await?;
    if let Some(error) = error {
        tracing::warn!(delivery_id=%job.id,error,"Back-channel logout failed; retry scheduled");
    }
    Ok(true)
}
async fn send(state: &AppState, job: &Delivery) -> Result<(), &'static str> {
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let claims = serde_json::json!({"iss":state.config.oidc.issuer,"aud":job.identifier,"sub":job.user_id.to_string(),"sid":job.session_id.to_string(),"iat":now,"exp":now+120,"jti":job.id.to_string(),"events":{"http://schemas.openid.net/event/backchannel-logout":{}}});
    send_signed(state, &job.endpoint, "logout+jwt", "logout_token", &claims).await
}

pub(super) async fn send_signed(
    state: &AppState,
    endpoint: &str,
    token_type: &str,
    field: &str,
    claims: &serde_json::Value,
) -> Result<(), &'static str> {
    pero_utils::redirect::validate_provider_endpoint_uri(endpoint)
        .map_err(|_| "invalid_endpoint")?;
    let txn = state.db.begin().await.map_err(|_| "database_error")?;
    let key = crate::db::helper::signing_key::require_active_signing_key(&txn)
        .await
        .map_err(|_| "signing_unavailable")?;
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some(key.kid);
    header.typ = Some(token_type.into());
    let token = jsonwebtoken::encode(
        &header,
        claims,
        &jsonwebtoken::EncodingKey::from_rsa_pem(key.private_key.as_bytes())
            .map_err(|_| "signing_unavailable")?,
    )
    .map_err(|_| "signing_unavailable")?;
    txn.commit().await.map_err(|_| "database_error")?;
    state
        .http_client
        .post(endpoint)
        .no_retry()
        .form(&[(field, token)])
        .send()
        .await
        .map_err(|_| "delivery_failed")?;
    Ok(())
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
                        tracing::error!(%error,"Back-channel logout queue unavailable");
                        break;
                    }
                }
            }
        }
    })
}
