//! Application device admission and independent OAuth client session identities.
use sea_orm::{ConnectionTrait, DbBackend, DbErr, FromQueryResult, Statement};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

#[derive(FromQueryResult)]
pub struct Device {
    pub id: Uuid,
    pub revoked: bool,
}

#[derive(FromQueryResult)]
struct Id {
    id: Uuid,
}

fn cutoff(idle_ttl: u64) -> OffsetDateTime {
    OffsetDateTime::now_utc() - Duration::seconds(idle_ttl as i64)
}

pub async fn latest<C: ConnectionTrait>(
    db: &C, user: Uuid, app: Uuid, sso: Uuid,
) -> Result<Option<Device>, DbErr> {
    Device::find_by_statement(Statement::from_sql_and_values(DbBackend::Postgres,
        "SELECT id,revoked_at IS NOT NULL AS revoked FROM app_sessions
         WHERE user_id=$1 AND app_id=$2 AND sso_session_id=$3
         ORDER BY created_at DESC,id DESC LIMIT 1",
        [user.into(), app.into(), sso.into()],
    )).one(db).await
}

pub async fn needs_confirmation<C: ConnectionTrait>(
    db: &C, user: Uuid, app: Uuid, sso: Uuid, idle_ttl: u64,
) -> Result<bool, DbErr> {
    if let Some(device) = latest(db, user, app, sso).await? {
        return Ok(device.revoked);
    }
    let row = db.query_one_raw(Statement::from_sql_and_values(DbBackend::Postgres,
        "SELECT a.max_sessions>0 AND
            (SELECT count(*) FROM app_sessions d JOIN sso_sessions s ON s.id=d.sso_session_id
             WHERE d.app_id=a.id AND d.user_id=$1 AND d.revoked_at IS NULL
               AND s.revoked_at IS NULL AND s.expires_at>now() AND s.last_seen_at>$3)>=a.max_sessions AS full
         FROM apps a WHERE a.id=$2",
        [user.into(), app.into(), cutoff(idle_ttl).into()],
    )).await?;
    row.map(|r| r.try_get("", "full")).transpose().map(|v| v.unwrap_or(true))
}

pub async fn admit<C: ConnectionTrait>(
    db: &C, access: &super::access::GrantAccess,
    code: &crate::db::entity::authorization_codes::Model, sso: Uuid, idle_ttl: u64,
) -> Result<Option<Uuid>, DbErr> {
    // Caller holds the app and user/app access locks through issuance.
    let current = latest(db, access.user.id, access.app.id, sso).await?;
    if current.as_ref().map(|d| d.id) != code.admission_session_id
        || current.as_ref().is_some_and(|d| d.revoked) != code.admission_revoked
    {
        return Ok(None);
    }
    let app_session = if let Some(device) = current.filter(|d| !d.revoked) {
        if db.query_one_raw(Statement::from_sql_and_values(DbBackend::Postgres,
            "SELECT id FROM app_sessions WHERE id=$1 AND revoked_at IS NULL FOR UPDATE",
            [device.id.into()])).await?.is_none() {
            return Ok(None);
        }
        device.id
    } else {
        if !code.takeover_allowed && needs_confirmation(db, access.user.id, access.app.id, sso, idle_ttl).await? {
            return Ok(None);
        }
        let id = Uuid::now_v7();
        db.execute_raw(Statement::from_sql_and_values(DbBackend::Postgres,
            "INSERT INTO app_sessions(id,user_id,app_id,sso_session_id) VALUES($1,$2,$3,$4)",
            [id.into(),access.user.id.into(),access.app.id.into(),sso.into()])).await?;
        if access.app.max_sessions > 0 {
            db.execute_raw(Statement::from_sql_and_values(DbBackend::Postgres,
                "UPDATE app_sessions SET revoked_at=clock_timestamp(),revoke_reason='session_limit_exceeded'
                 WHERE id IN (SELECT d.id FROM app_sessions d JOIN sso_sessions s ON s.id=d.sso_session_id
                  WHERE d.app_id=$1 AND d.user_id=$2 AND d.id<>$3 AND d.revoked_at IS NULL
                    AND s.revoked_at IS NULL AND s.expires_at>now() AND s.last_seen_at>$4
                  ORDER BY d.created_at DESC,d.id DESC OFFSET $5)",
                [access.app.id.into(),access.user.id.into(),id.into(),cutoff(idle_ttl).into(),
                 (i64::from(access.app.max_sessions)-1).into()])).await?;
        }
        id
    };
    let id = Id::find_by_statement(Statement::from_sql_and_values(DbBackend::Postgres,
        "INSERT INTO client_sessions(app_session_id,client_id,tenant_id) VALUES($1,$2,$3)
         ON CONFLICT(app_session_id,client_id,tenant_id) WHERE revoked_at IS NULL
         DO UPDATE SET client_id=EXCLUDED.client_id RETURNING id",
        [app_session.into(),code.client_id.into(),code.tenant_id.into()])).one(db).await?
        .ok_or_else(|| DbErr::RecordNotFound("client session".into()))?.id;
    Ok(Some(id))
}

/// Resolve a signed RP sid to its parent. Callers also check SSO lifetime and grant policy.
pub async fn sso_for_client<C: ConnectionTrait>(
    db: &C, sid: Uuid, user: Uuid, client: Uuid, app: Uuid, tenant: Option<Uuid>,
) -> Result<Option<Uuid>, DbErr> {
    Ok(Id::find_by_statement(Statement::from_sql_and_values(DbBackend::Postgres,
        "SELECT a.sso_session_id AS id FROM client_sessions c JOIN app_sessions a ON a.id=c.app_session_id
         WHERE c.id=$1 AND a.user_id=$2 AND c.client_id=$3 AND a.app_id=$4
           AND c.tenant_id IS NOT DISTINCT FROM $5 AND c.revoked_at IS NULL AND a.revoked_at IS NULL",
        [sid.into(),user.into(),client.into(),app.into(),tenant.into()])).one(db).await?.map(|r|r.id))
}

pub async fn prune<C: ConnectionTrait>(
    db: &C, app: Uuid, limit: i32, idle_ttl: u64,
) -> Result<(), DbErr> {
    db.execute_raw(Statement::from_sql_and_values(DbBackend::Postgres,
        "UPDATE app_sessions SET revoked_at=clock_timestamp(),revoke_reason='session_limit_changed'
         WHERE id IN (SELECT id FROM (SELECT d.id,row_number() OVER
         (PARTITION BY d.user_id ORDER BY d.created_at DESC,d.id DESC) AS rank
         FROM app_sessions d JOIN sso_sessions s ON s.id=d.sso_session_id
         WHERE d.app_id=$1 AND d.revoked_at IS NULL AND s.revoked_at IS NULL
           AND s.expires_at>now() AND s.last_seen_at>$2) ranked WHERE rank>$3)",
        [app.into(),cutoff(idle_ttl).into(),i64::from(limit).into()])).await?;
    Ok(())
}

pub async fn revoke_client<C: ConnectionTrait>(
    db: &C, sid: Uuid, user: Uuid, client: Uuid, reason: &str,
) -> Result<(), DbErr> {
    let Some(parent) = Id::find_by_statement(Statement::from_sql_and_values(DbBackend::Postgres,
        "SELECT a.id FROM app_sessions a JOIN client_sessions c ON c.app_session_id=a.id
         WHERE c.id=$1 AND a.user_id=$2 AND c.client_id=$3 AND a.revoked_at IS NULL FOR UPDATE OF a",
        [sid.into(),user.into(),client.into()])).one(db).await? else { return Ok(()) };
    db.execute_raw(Statement::from_sql_and_values(DbBackend::Postgres,
        "UPDATE client_sessions SET revoked_at=clock_timestamp(),revoke_reason=$2 WHERE id=$1 AND revoked_at IS NULL",
        [sid.into(),reason.into()])).await?;
    db.execute_raw(Statement::from_sql_and_values(DbBackend::Postgres,
        "UPDATE app_sessions a SET revoked_at=clock_timestamp(),revoke_reason=$2 WHERE a.id=$1
         AND a.revoked_at IS NULL AND NOT EXISTS (SELECT 1 FROM client_sessions c WHERE c.app_session_id=a.id AND c.revoked_at IS NULL)",
        [parent.id.into(),reason.into()])).await?;
    Ok(())
}

#[derive(FromQueryResult, serde::Serialize)]
pub struct DeviceRow {
    pub id: Uuid,
    pub app_id: Uuid,
    pub sso_session_id: Uuid,
    pub app_name: String,
    pub max_sessions: i32,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

/// The caller supplies the authenticated user and the already validated SSO page.
pub async fn devices<C: ConnectionTrait>(
    db: &C, user: Uuid, sessions: Vec<Uuid>,
) -> Result<Vec<DeviceRow>, DbErr> {
    if sessions.is_empty() {
        return Ok(Vec::new());
    }
    DeviceRow::find_by_statement(Statement::from_sql_and_values(DbBackend::Postgres,
        "SELECT d.id,d.app_id,d.sso_session_id,a.name AS app_name,a.max_sessions,d.created_at
         FROM app_sessions d JOIN apps a ON a.id=d.app_id
         WHERE d.user_id=$1 AND d.sso_session_id=ANY($2::uuid[]) AND d.revoked_at IS NULL
         ORDER BY d.created_at DESC,d.id DESC",
        [user.into(),sessions.into()])).all(db).await
}

/// Called under the user's security lock; never changes the global SSO session.
pub async fn revoke_device<C: ConnectionTrait>(
    db: &C, user: Uuid, device: Uuid, reason: &str,
) -> Result<(), DbErr> {
    db.execute_raw(Statement::from_sql_and_values(DbBackend::Postgres,
        "UPDATE app_sessions SET revoked_at=clock_timestamp(),revoke_reason=$3
         WHERE id=$1 AND user_id=$2 AND revoked_at IS NULL",
        [device.into(),user.into(),reason.into()])).await?;
    Ok(())
}

pub async fn revoke_other_devices<C: ConnectionTrait>(
    db: &C, user: Uuid, app: Uuid, current: Uuid,
) -> Result<(), DbErr> {
    db.execute_raw(Statement::from_sql_and_values(DbBackend::Postgres,
        "UPDATE app_sessions SET revoked_at=clock_timestamp(),revoke_reason='user_revoked'
         WHERE user_id=$1 AND app_id=$2 AND sso_session_id<>$3 AND revoked_at IS NULL",
        [user.into(),app.into(),current.into()])).await?;
    Ok(())
}
