//! Organization-owned application requests; only platform administrators approve grants.
use super::ManagementError as Error;
use sea_orm::{ConnectionTrait, DatabaseConnection, DbBackend, Statement, TransactionTrait};
use uuid::Uuid;

pub async fn change(
    db: &DatabaseConnection,
    actor: Uuid,
    tenant: Uuid,
    app: Uuid,
    action: &str,
) -> Result<(), Error> {
    if !matches!(action, "request" | "withdraw") {
        return Err(Error::Invalid("invalid_request"));
    }
    let txn = db.begin().await?;
    txn.query_one_raw(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "SELECT id FROM tenants WHERE id=$1 AND kind='organization' AND status='active' FOR UPDATE",
        [tenant.into()],
    ))
    .await?
    .ok_or(Error::Invalid("not_found"))?;
    let owner = txn.query_one_raw(Statement::from_sql_and_values(DbBackend::Postgres,
        "SELECT 1 FROM tenant_members m JOIN users u ON u.id=m.user_id WHERE m.tenant_id=$1 AND m.user_id=$2 AND m.role='owner' AND m.status='active' AND u.status='active' AND u.deleted_at IS NULL",
        [tenant.into(),actor.into()])).await?.is_some();
    if !owner {
        return Err(Error::Invalid("forbidden"));
    }
    txn.query_one_raw(Statement::from_sql_and_values(DbBackend::Postgres,
        "SELECT id FROM apps WHERE id=$1 AND status='active' AND NOT system AND tenant_mode IN ('organization','both') AND organization_access='restricted'",
        [app.into()])).await?.ok_or(Error::Invalid("invalid_app"))?;
    if action == "request" {
        let granted = txn
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "SELECT 1 FROM tenant_app_grants WHERE tenant_id=$1 AND app_id=$2",
                [tenant.into(), app.into()],
            ))
            .await?
            .is_some();
        if granted {
            return Err(Error::Invalid("already_granted"));
        }
        txn.execute_raw(Statement::from_sql_and_values(DbBackend::Postgres,
            "INSERT INTO tenant_app_requests(tenant_id,app_id,requested_by,status) VALUES($1,$2,$3,'pending') ON CONFLICT(tenant_id,app_id) DO UPDATE SET status='pending',requested_by=EXCLUDED.requested_by,reviewed_by=NULL,reviewed_at=NULL,updated_at=now() WHERE tenant_app_requests.status<>'pending'",
            [tenant.into(),app.into(),actor.into()])).await?;
    } else {
        let updated=txn.execute_raw(Statement::from_sql_and_values(DbBackend::Postgres,
            "UPDATE tenant_app_requests SET status='withdrawn',updated_at=now() WHERE tenant_id=$1 AND app_id=$2 AND status='pending'",
            [tenant.into(),app.into()])).await?.rows_affected();
        if updated == 0 {
            return Err(Error::Invalid("not_found"));
        }
    }
    txn.execute_raw(Statement::from_sql_and_values(DbBackend::Postgres,
        "INSERT INTO audit_events(actor_id,actor_username,action,target,outcome,http_status) SELECT id,username,$2,$3,'success',200 FROM users WHERE id=$1",
        [actor.into(),format!("tenant.app.{action}").into(),format!("{tenant}/{app}").into()])).await?;
    txn.commit().await?;
    Ok(())
}
