//! Per-user organization quota and expansion gate; personal workspaces are never counted.
use super::ManagementError as Error;
use sea_orm::{
    ConnectionTrait, DatabaseConnection, DatabaseTransaction, DbBackend, FromQueryResult,
    Statement, TransactionTrait,
};
use serde::Serialize;
use uuid::Uuid;

type Result<T> = std::result::Result<T, Error>;

#[derive(FromQueryResult, Serialize)]
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
#[derive(FromQueryResult)]
struct IdRow {
    id: Uuid,
}

pub async fn read<C: ConnectionTrait>(db: &C, user: Uuid) -> Result<TenantPolicy> {
    TenantPolicy::find_by_statement(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "SELECT COALESCE(p.enabled,false) AS enabled,COALESCE(p.max_tenants,0) AS max_tenants,(SELECT count(*)::bigint FROM tenants t WHERE t.kind='organization' AND t.created_by=u.id) AS tenant_count FROM users u LEFT JOIN tenant_creation_policies p ON p.user_id=u.id WHERE u.id=$1 AND u.deleted_at IS NULL",
        [user.into()],
    ))
    .one(db)
    .await?
    .ok_or(Error::Invalid("not_found"))
}

pub async fn creator<C: ConnectionTrait>(db: &C, tenant: Uuid) -> Result<Option<Uuid>> {
    let row = db.query_one_raw(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "SELECT created_by FROM tenants WHERE id=$1 AND kind='organization'",
        [tenant.into()],
    ))
    .await?
    .ok_or(Error::Invalid("not_found"))?;
    Ok(row.try_get("", "created_by")?)
}

/// A missing policy is disabled; never manufacture implicit permissions.
async fn lock<C: ConnectionTrait>(db: &C, user: Uuid) -> Result<Option<PolicyRow>> {
    Ok(PolicyRow::find_by_statement(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "SELECT enabled,max_tenants FROM tenant_creation_policies WHERE user_id=$1 FOR UPDATE",
        [user.into()],
    ))
    .one(db)
    .await?)
}

pub async fn lock_if_present<C: ConnectionTrait>(db: &C, user: Option<Uuid>) -> Result<()> {
    if let Some(user) = user {
        lock(db, user).await?;
    }
    Ok(())
}

async fn count<C: ConnectionTrait>(db: &C, user: Uuid) -> Result<i64> {
    Ok(CountRow::find_by_statement(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "SELECT count(*)::bigint AS n FROM tenants WHERE created_by=$1 AND kind='organization'",
        [user.into()],
    ))
    .one(db)
    .await?
    .ok_or(Error::Invalid("not_found"))?
    .n)
}


pub async fn may_add_members<C: ConnectionTrait>(db: &C, tenant: Uuid) -> Result<bool> {
    let Some(creator) = creator(db, tenant).await? else {
        return Ok(false);
    };
    let policy = read(db, creator).await?;
    Ok(policy.enabled && policy.tenant_count <= i64::from(policy.max_tenants))
}

pub async fn authorize_create<C: ConnectionTrait>(db: &C, user: Uuid) -> Result<()> {
    let policy = lock(db, user).await?;
    if !policy.as_ref().is_some_and(|p| p.enabled) {
        return Err(Error::Invalid("tenant_creation_disabled"));
    }
    let max = policy.expect("checked").max_tenants as i64;
    if count(db, user).await? >= max {
        return Err(Error::Invalid("tenant_creation_limit"));
    }
    Ok(())
}

/// Existing tenants remain manageable. Only new memberships are rejected when
/// creation has been disabled or the creator remains above their reduced quota.
/// Equality with the quota blocks new organizations, not members of existing ones.
pub async fn authorize_members<C: ConnectionTrait>(
    db: &C,
    creator: Option<Uuid>,
) -> Result<()> {
    let user = creator.ok_or(Error::Invalid("tenant_expansion_disabled"))?;
    let policy = lock(db, user).await?;
    if !policy.as_ref().is_some_and(|p| p.enabled) {
        return Err(Error::Invalid("tenant_expansion_disabled"));
    }
    if count(db, user).await? > i64::from(policy.expect("checked").max_tenants) {
        return Err(Error::Invalid("tenant_creation_limit"));
    }
    Ok(())
}

/// Called while holding the creator policy row; any simultaneous creation or
/// invitation acceptance uses the same row lock. Delete newest empty spaces first.
/// Exactly one ACTIVE owner and no other ACTIVE member is an empty organization.
pub async fn prune_excess(
    txn: &DatabaseTransaction,
    creator: Uuid,
    actor: Uuid,
) -> Result<u64> {
    let policy = PolicyRow::find_by_statement(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "SELECT enabled,max_tenants FROM tenant_creation_policies WHERE user_id=$1",
        [creator.into()],
    ))
    .one(txn)
    .await?;
    let Some(policy) = policy else { return Ok(0) };
    let mut excess = count(txn, creator).await? - i64::from(policy.max_tenants);
    if excess <= 0 {
        return Ok(0);
    }
    let candidates = IdRow::find_by_statement(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "SELECT t.id FROM tenants t WHERE t.created_by=$1 AND t.kind='organization' AND (SELECT count(*) FROM tenant_members m WHERE m.tenant_id=t.id AND m.status='active')=1 AND EXISTS (SELECT 1 FROM tenant_members m WHERE m.tenant_id=t.id AND m.role='owner' AND m.status='active') ORDER BY t.created_at DESC,t.id DESC",
        [creator.into()],
    ))
    .all(txn)
    .await?;
    let mut deleted=0;
    for candidate in candidates {
        if excess == 0 { break; }
        // Role changes and member removals lock this organization row first.
        txn.query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT id FROM tenants WHERE id=$1 FOR UPDATE",
            [candidate.id.into()],
        )).await?;
        let empty=txn.query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT id FROM tenants t WHERE t.id=$1 AND (SELECT count(*) FROM tenant_members m WHERE m.tenant_id=t.id AND m.status='active')=1 AND EXISTS(SELECT 1 FROM tenant_members m WHERE m.tenant_id=t.id AND m.role='owner' AND m.status='active')",
            [candidate.id.into()],
        )).await?.is_some();
        if !empty { continue; }
        let tenant = candidate.id;
        // The old authorization state must never survive as an unbound grant.
        txn.execute_raw(Statement::from_sql_and_values(DbBackend::Postgres,
            "UPDATE refresh_tokens SET tenant_id=NULL,revoked_at=COALESCE(revoked_at,now()),revoke_reason=COALESCE(revoke_reason,'tenant_deleted') WHERE tenant_id=$1",[tenant.into()])).await?;
        txn.execute_raw(Statement::from_sql_and_values(DbBackend::Postgres,
            "UPDATE authorization_codes SET tenant_id=NULL,consumed_at=COALESCE(consumed_at,now()) WHERE tenant_id=$1",[tenant.into()])).await?;
        txn.execute_raw(Statement::from_sql_and_values(DbBackend::Postgres,
            "UPDATE authorization_requests SET tenant_id=NULL,completed_at=COALESCE(completed_at,now()) WHERE tenant_id=$1",[tenant.into()])).await?;
        // A tenant-scoped sync delivery is cascaded on deletion; a user-level
        // resync survives and lets receiving apps reconcile removed memberships.
        txn.execute_raw(Statement::from_sql_and_values(DbBackend::Postgres,
            "INSERT INTO account_sync_deliveries(client_id,user_id,kind,endpoint) SELECT c.id,m.user_id,'sync.requested',c.account_sync_uri FROM tenant_members m JOIN user_app_access a ON a.user_id=m.user_id AND a.status='active' JOIN apps app ON app.id=a.app_id JOIN oauth_clients c ON c.app_id=app.id WHERE m.tenant_id=$1 AND m.status='active' AND c.status='active' AND c.account_sync_uri IS NOT NULL AND (app.tenant_mode='both' OR app.tenant_mode='organization')",[tenant.into()])).await?;
        txn.execute_raw(Statement::from_sql_and_values(DbBackend::Postgres,
            "DELETE FROM tenants WHERE id=$1",[tenant.into()])).await?;
        txn.execute_raw(Statement::from_sql_and_values(DbBackend::Postgres,
            "INSERT INTO audit_events(actor_id,actor_username,action,target,outcome,http_status) SELECT id,username,'tenant.quota.empty_deleted',$2,'success',200 FROM users WHERE id=$1",
            [actor.into(),tenant.to_string().into()])).await?;
        deleted += 1;
        excess -= 1;
    }
    Ok(deleted)
}

pub async fn update(
    db: &DatabaseConnection,
    actor: &super::permissions::Actor,
    user: Uuid,
    enabled: bool,
    max_tenants: i32,
) -> Result<()> {
    if !(0..=10_000).contains(&max_tenants) {
        return Err(Error::Invalid("invalid_request"));
    }
    let txn=db.begin().await?;
    super::permissions::require_super(&txn,actor).await?;
    // Ensure this user exists, then create one explicitly admin-managed policy.
    let valid=txn.query_one_raw(Statement::from_sql_and_values(DbBackend::Postgres,
        "SELECT id FROM users WHERE id=$1 AND deleted_at IS NULL",[user.into()])).await?.is_some();
    if !valid { return Err(Error::Invalid("not_found")); }
    txn.execute_raw(Statement::from_sql_and_values(DbBackend::Postgres,
        "INSERT INTO tenant_creation_policies(user_id) VALUES($1) ON CONFLICT DO NOTHING",[user.into()])).await?;
    lock(&txn,user).await?;
    txn.execute_raw(Statement::from_sql_and_values(DbBackend::Postgres,
        "UPDATE tenant_creation_policies SET enabled=$2,max_tenants=$3,updated_by=$4,updated_at=now() WHERE user_id=$1",
        [user.into(),enabled.into(),max_tenants.into(),actor.session.user_id.into()])).await?;
    let removed=prune_excess(&txn,user,actor.session.user_id).await?;
    let details=serde_json::json!({"enabled":enabled,"max_tenants":max_tenants,"removed_empty_tenants":removed});
    txn.execute_raw(Statement::from_sql_and_values(DbBackend::Postgres,
        "INSERT INTO audit_events(actor_id,actor_username,action,target,outcome,http_status,details) SELECT id,username,'tenant.creation.policy.updated',$2,'success',200,$3 FROM users WHERE id=$1",
        [actor.session.user_id.into(),user.to_string().into(),details.into()])).await?;
    txn.commit().await?;
    Ok(())
}
