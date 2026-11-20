//! Organization creation quotas govern creation only, never an existing organization's membership.
use super::ManagementError as Error;
use sea_orm::{
    ConnectionTrait, DatabaseConnection, DbBackend, FromQueryResult, Statement, TransactionTrait,
};
use serde::Serialize;
use uuid::Uuid;

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, FromQueryResult, Serialize)]
pub struct TenantPolicy {
    pub enabled: bool,
    pub max_tenants: i32,
    pub tenant_count: i64,
}

#[derive(FromQueryResult)]
struct PolicyRow {
    enabled: bool,
    max_tenants: i32,
}

#[derive(FromQueryResult)]
struct CountRow {
    n: i64,
}

pub async fn read<C: ConnectionTrait>(db: &C, user: Uuid) -> Result<TenantPolicy> {
    TenantPolicy::find_by_statement(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "SELECT COALESCE(p.enabled,false) AS enabled,COALESCE(p.max_tenants,0) AS max_tenants,(SELECT count(*)::bigint FROM tenants t WHERE t.kind='organization' AND t.status<>'deleted' AND t.created_by=u.id) AS tenant_count FROM users u LEFT JOIN tenant_creation_policies p ON p.user_id=u.id WHERE u.id=$1 AND u.deleted_at IS NULL",
        [user.into()],
    ))
    .one(db)
    .await?
    .ok_or(Error::Invalid("not_found"))
}

/// Lock the creator's policy before counting to serialize concurrent creations and quota updates.
pub async fn authorize_create<C: ConnectionTrait>(db: &C, user: Uuid) -> Result<()> {
    let policy = PolicyRow::find_by_statement(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "SELECT enabled,max_tenants FROM tenant_creation_policies WHERE user_id=$1 FOR UPDATE",
        [user.into()],
    ))
    .one(db)
    .await?
    .filter(|p| p.enabled)
    .ok_or(Error::Invalid("tenant_creation_disabled"))?;
    let count = CountRow::find_by_statement(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "SELECT count(*)::bigint AS n FROM tenants WHERE created_by=$1 AND kind='organization' AND status<>'deleted'",
        [user.into()],
    ))
    .one(db)
    .await?
    .ok_or(Error::Invalid("not_found"))?;
    if count.n >= i64::from(policy.max_tenants) {
        return Err(Error::Invalid("tenant_creation_limit"));
    }
    Ok(())
}

/// Lowering a quota never deletes, disables or changes any existing organization.
pub async fn update(
    db: &DatabaseConnection,
    actor: &super::permissions::Actor,
    user: Uuid,
    enabled: bool,
    max_tenants: i32,
) -> Result<()> {
    if max_tenants < 0 {
        return Err(Error::Invalid("invalid_request"));
    }
    let txn = db.begin().await?;
    super::permissions::require_super(&txn, actor).await?;
    let valid = txn
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT id FROM users WHERE id=$1 AND deleted_at IS NULL",
            [user.into()],
        ))
        .await?
        .is_some();
    if !valid {
        return Err(Error::Invalid("not_found"));
    }
    txn.execute_raw(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "INSERT INTO tenant_creation_policies(user_id) VALUES($1) ON CONFLICT DO NOTHING",
        [user.into()],
    ))
    .await?;
    txn.execute_raw(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "UPDATE tenant_creation_policies SET enabled=$2,max_tenants=$3,updated_by=$4,updated_at=now() WHERE user_id=$1",
        [user.into(),enabled.into(),max_tenants.into(),actor.session.user_id.into()],
    )).await?;
    let details = serde_json::json!({"enabled":enabled,"max_tenants":max_tenants});
    txn.execute_raw(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "INSERT INTO audit_events(actor_id,actor_username,action,target,outcome,http_status,details) SELECT id,username,'tenant.creation.policy.updated',$2,'success',200,$3 FROM users WHERE id=$1",
        [actor.session.user_id.into(),user.to_string().into(),details.into()],
    )).await?;
    txn.commit().await?;
    Ok(())
}
