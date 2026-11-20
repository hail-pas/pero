//! The only reusable live tenant-context decision. Business permissions stay in applications.
use sea_orm::{ConnectionTrait, DbBackend, DbErr, FromQueryResult, Statement};
use serde::Serialize;
use uuid::Uuid;

#[derive(Debug, Clone, FromQueryResult, Serialize)]
pub struct TenantContext {
    pub tenant_id: Uuid,
    pub tenant_kind: String,
    pub tenant_version: i64,
    pub tenant_member_version: i64,
}
#[derive(Debug, Clone, FromQueryResult, Serialize)]
pub struct TenantChoice {
    pub id: Uuid,
    pub kind: String,
    pub name: String,
    pub role: String,
}
pub async fn choices<C: ConnectionTrait>(
    db: &C,
    user: Uuid,
    app: Uuid,
) -> Result<Vec<TenantChoice>, DbErr> {
    TenantChoice::find_by_statement(Statement::from_sql_and_values(DbBackend::Postgres,
        "SELECT t.id,t.kind,t.name,m.role FROM tenants t JOIN tenant_members m ON m.tenant_id=t.id JOIN apps a ON a.id=$2 JOIN users u ON u.id=m.user_id WHERE m.user_id=$1 AND u.status='active' AND u.deleted_at IS NULL AND m.status='active' AND t.status='active' AND a.status='active' AND (a.tenant_mode='both' OR a.tenant_mode=t.kind) AND (t.kind='personal' OR a.organization_access='open' OR EXISTS (SELECT 1 FROM tenant_app_grants g WHERE g.tenant_id=t.id AND g.app_id=a.id)) ORDER BY (t.kind='personal') DESC,t.name,t.id",
        [user.into(),app.into()])).all(db).await
}
pub async fn active<C: ConnectionTrait>(
    db: &C,
    user: Uuid,
    app: Uuid,
    tenant: Uuid,
) -> Result<Option<TenantContext>, DbErr> {
    TenantContext::find_by_statement(Statement::from_sql_and_values(DbBackend::Postgres,
        "SELECT t.id AS tenant_id,t.kind AS tenant_kind,t.auth_version AS tenant_version,m.auth_version AS tenant_member_version FROM tenants t JOIN tenant_members m ON m.tenant_id=t.id JOIN apps a ON a.id=$3 JOIN users u ON u.id=m.user_id WHERE t.id=$1 AND u.status='active' AND u.deleted_at IS NULL AND m.user_id=$2 AND m.status='active' AND t.status='active' AND a.status='active' AND (a.tenant_mode='both' OR a.tenant_mode=t.kind) AND (t.kind='personal' OR a.organization_access='open' OR EXISTS (SELECT 1 FROM tenant_app_grants g WHERE g.tenant_id=t.id AND g.app_id=a.id))",
        [tenant.into(),user.into(),app.into()])).one(db).await
}
pub async fn resolve<C: ConnectionTrait>(
    db: &C,
    user: Uuid,
    app: Uuid,
    requested: Option<Uuid>,
) -> Result<Option<TenantContext>, DbErr> {
    if let Some(tenant) = requested {
        return active(db, user, app, tenant).await;
    }
    let options = choices(db, user, app).await?;
    if options.len() != 1 {
        return Ok(None);
    }
    active(db, user, app, options[0].id).await
}
#[derive(Debug, Clone, FromQueryResult, Serialize)]
pub struct MembershipSnapshot {
    pub tenant_kind: String,
    pub tenant_status: String,
    pub membership_status: String,
    pub tenant_version: i64,
    pub membership_version: i64,
    pub app_allowed: bool,
}

/// Current membership including inactive states, only for the authenticated app's user.
pub async fn snapshot<C: ConnectionTrait>(
    db: &C,
    user: Uuid,
    app: Uuid,
    tenant: Uuid,
) -> Result<Option<MembershipSnapshot>, DbErr> {
    MembershipSnapshot::find_by_statement(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "SELECT t.kind AS tenant_kind,t.status AS tenant_status,m.status AS membership_status,t.auth_version AS tenant_version,m.auth_version AS membership_version,(t.kind='personal' OR a.organization_access='open' OR EXISTS (SELECT 1 FROM tenant_app_grants g WHERE g.tenant_id=t.id AND g.app_id=a.id)) AS app_allowed FROM tenants t JOIN tenant_members m ON m.tenant_id=t.id JOIN users u ON u.id=m.user_id JOIN apps a ON a.id=$3 WHERE t.id=$1 AND m.user_id=$2 AND u.status='active' AND u.deleted_at IS NULL AND a.status='active' AND (a.tenant_mode='both' OR a.tenant_mode=t.kind)",
        [tenant.into(), user.into(), app.into()],
    ))
    .one(db)
    .await
}
