//! The only reusable live tenant-context decision. Business permissions stay in applications.
use sea_orm::{ConnectionTrait, DbBackend, DbErr, FromQueryResult, Statement};
use serde::Serialize;
use uuid::Uuid;

#[derive(Debug, Clone, FromQueryResult, Serialize)]
pub struct TenantContext {
    pub tenant_id: Uuid,
    pub tenant_kind: String,
    pub membership_role: String,
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
        "SELECT t.id,t.kind,t.name,m.role FROM tenants t JOIN tenant_members m ON m.tenant_id=t.id JOIN apps a ON a.id=$2 JOIN users u ON u.id=m.user_id WHERE m.user_id=$1 AND u.status='active' AND u.deleted_at IS NULL AND m.status='active' AND t.status='active' AND a.status='active' AND (a.tenant_mode='both' OR a.tenant_mode=t.kind) AND (t.kind='personal' OR a.organization_access='open' OR EXISTS (SELECT 1 FROM tenant_app_grants g WHERE g.tenant_id=t.id AND g.app_id=a.id)) AND EXISTS (SELECT 1 FROM user_app_access ua WHERE ua.app_id=a.id AND ua.user_id=m.user_id AND ua.status='active' AND (ua.admission_origin='explicit' OR (ua.admission_origin='organization' AND a.organization_auto_access AND t.kind='organization'))) ORDER BY (t.kind='personal') DESC,t.name,t.id",
        [user.into(),app.into()])).all(db).await
}
pub async fn active<C: ConnectionTrait>(
    db: &C,
    user: Uuid,
    app: Uuid,
    tenant: Uuid,
) -> Result<Option<TenantContext>, DbErr> {
    TenantContext::find_by_statement(Statement::from_sql_and_values(DbBackend::Postgres,
        "SELECT t.id AS tenant_id,t.kind AS tenant_kind,m.role AS membership_role,t.auth_version AS tenant_version,m.auth_version AS tenant_member_version FROM tenants t JOIN tenant_members m ON m.tenant_id=t.id JOIN apps a ON a.id=$3 JOIN users u ON u.id=m.user_id WHERE t.id=$1 AND u.status='active' AND u.deleted_at IS NULL AND m.user_id=$2 AND m.status='active' AND t.status='active' AND a.status='active' AND (a.tenant_mode='both' OR a.tenant_mode=t.kind) AND (t.kind='personal' OR a.organization_access='open' OR EXISTS (SELECT 1 FROM tenant_app_grants g WHERE g.tenant_id=t.id AND g.app_id=a.id)) AND EXISTS (SELECT 1 FROM user_app_access ua WHERE ua.app_id=a.id AND ua.user_id=m.user_id AND ua.status='active' AND (ua.admission_origin='explicit' OR (ua.admission_origin='organization' AND a.organization_auto_access AND t.kind='organization')))",
        [tenant.into(),user.into(),app.into()])).one(db).await
}
/// Whether the user belongs to any currently admitted organization for this app.
/// Explicitly disabled user-app grants are still authoritative.
pub async fn auto_eligible<C: ConnectionTrait>(db: &C, user: Uuid, app: Uuid) -> Result<bool, DbErr> {
    let row = db.query_one_raw(Statement::from_sql_and_values(DbBackend::Postgres,
        "SELECT EXISTS(SELECT 1 FROM apps a JOIN tenant_members m ON m.user_id=$1 AND m.status='active' JOIN tenants t ON t.id=m.tenant_id AND t.kind='organization' AND t.status='active' WHERE a.id=$2 AND a.status='active' AND a.organization_auto_access AND a.tenant_mode IN ('organization','both') AND (a.organization_access='open' OR EXISTS(SELECT 1 FROM tenant_app_grants g WHERE g.tenant_id=t.id AND g.app_id=a.id))) AS eligible",
        [user.into(),app.into()])).await?;
    row.ok_or(DbErr::Custom("missing eligibility result".into()))?.try_get("", "eligible")
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
    pub tenant_name: String,
    pub membership_role: String,
    pub tenant_kind: String,
    pub tenant_status: String,
    pub membership_status: String,
    pub tenant_version: i64,
    pub membership_version: i64,
    pub app_allowed: bool,
    pub user_active: bool,
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
        "SELECT t.name AS tenant_name,m.role AS membership_role,t.kind AS tenant_kind,t.status AS tenant_status,m.status AS membership_status,t.auth_version AS tenant_version,m.auth_version AS membership_version,(a.status='active' AND (a.tenant_mode='both' OR a.tenant_mode=t.kind) AND (t.kind='personal' OR a.organization_access='open' OR EXISTS (SELECT 1 FROM tenant_app_grants g WHERE g.tenant_id=t.id AND g.app_id=a.id))) AS app_allowed,(u.status='active' AND u.deleted_at IS NULL) AS user_active FROM tenants t JOIN tenant_members m ON m.tenant_id=t.id JOIN users u ON u.id=m.user_id JOIN apps a ON a.id=$3 WHERE t.id=$1 AND m.user_id=$2 AND EXISTS (SELECT 1 FROM tenant_app_history h WHERE h.tenant_id=t.id AND h.user_id=m.user_id AND h.app_id=a.id)",
        [tenant.into(), user.into(), app.into()],
    ))
    .one(db)
    .await
}
