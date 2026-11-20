//! Platform-only organization governance; never administer business resources here.
use super::ManagementError as Error;
use sea_orm::{ConnectionTrait, DatabaseConnection, DbBackend, FromQueryResult, Statement, TransactionTrait};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
type Result<T> = std::result::Result<T,Error>;

#[derive(Default,Deserialize)]
pub struct Filter {pub page:Option<u64>,pub q:Option<String>,pub status:Option<String>}
#[derive(FromQueryResult,Serialize)]
pub struct Summary {
    pub id:Uuid,pub name:String,pub slug:Option<String>,pub status:String,
    pub created_by:Option<Uuid>,pub created_at:time::OffsetDateTime,
    pub max_members:i32,pub members:i64,pub owner_name:Option<String>,
}
#[derive(Serialize)]
pub struct Listing {pub rows:Vec<Summary>,pub page:u64,pub total_pages:u64,pub q:String,pub status:String}
const SELECT:&str="SELECT t.id,t.name,t.slug::text,t.status,t.created_by,t.created_at,t.max_members,(SELECT count(*)::bigint FROM tenant_members m WHERE m.tenant_id=t.id AND m.status='active') AS members,(SELECT u.username::text FROM tenant_members m JOIN users u ON u.id=m.user_id WHERE m.tenant_id=t.id AND m.role='owner' AND m.status='active' AND u.deleted_at IS NULL ORDER BY m.joined_at LIMIT 1) AS owner_name FROM tenants t WHERE t.kind='organization'";
pub async fn list<C:ConnectionTrait>(db:&C,input:&Filter)->Result<Listing>{
    let page=input.page.unwrap_or(1).clamp(1,1_000_000);
    let q=input.q.as_deref().unwrap_or("").trim().chars().take(100).collect::<String>();
    let status=input.status.as_deref().filter(|s|matches!(*s,"active"|"disabled"|"deleted")).unwrap_or("").to_owned();
    let clause=" AND ($1='' OR t.name ILIKE '%'||$1||'%' OR t.slug::text ILIKE '%'||$1||'%') AND ($2='' OR t.status=$2)";
    let total:i64=db.query_one_raw(Statement::from_sql_and_values(DbBackend::Postgres,
        format!("SELECT count(*)::bigint AS total FROM tenants t WHERE t.kind='organization'{clause}"),
        [q.clone().into(),status.clone().into()])).await?.ok_or(Error::Invalid("not_found"))?.try_get("","total")?;
    let rows=Summary::find_by_statement(Statement::from_sql_and_values(DbBackend::Postgres,
        format!("{SELECT}{clause} ORDER BY t.created_at DESC,t.id DESC LIMIT 20 OFFSET $3"),
        [q.clone().into(),status.clone().into(),(((page-1)*20) as i64).into()])).all(db).await?;
    Ok(Listing{rows,page,total_pages:((total.max(0) as u64)+19)/20,q,status})
}
pub async fn get<C:ConnectionTrait>(db:&C,id:Uuid)->Result<Summary>{
    Summary::find_by_statement(Statement::from_sql_and_values(DbBackend::Postgres,
        format!("{SELECT} AND t.id=$1"),[id.into()])).one(db).await?.ok_or(Error::Invalid("not_found"))
}
#[derive(Default,Deserialize)]
pub struct MemberFilter {pub member_page:Option<u64>,pub member_q:Option<String>}
#[derive(Serialize)]
pub struct Members {pub rows:Vec<super::tenant::Member>,pub page:u64,pub total_pages:u64,pub q:String}
pub async fn members<C:ConnectionTrait>(db:&C,tenant:Uuid,input:&MemberFilter)->Result<Members>{
    let page=input.member_page.unwrap_or(1).clamp(1,1_000_000);
    let q=input.member_q.as_deref().unwrap_or("").trim().chars().take(100).collect::<String>();
    let from=" FROM tenant_members m JOIN users u ON u.id=m.user_id WHERE m.tenant_id=$1 AND m.status='active' AND ($2='' OR u.username::text ILIKE '%'||$2||'%' OR u.nickname ILIKE '%'||$2||'%')";
    let count:i64=db.query_one_raw(Statement::from_sql_and_values(DbBackend::Postgres,
        format!("SELECT count(*)::bigint AS n{from}"),[tenant.into(),q.clone().into()])).await?
        .ok_or(Error::Invalid("not_found"))?.try_get("","n")?;
    let rows=super::tenant::Member::find_by_statement(Statement::from_sql_and_values(DbBackend::Postgres,
        format!("SELECT m.user_id,u.username::text,COALESCE(u.nickname,u.username::text) AS name,m.role,m.status{from} ORDER BY (m.role='owner') DESC,m.joined_at LIMIT 20 OFFSET $3"),
        [tenant.into(),q.clone().into(),(((page-1)*20) as i64).into()])).all(db).await?;
    Ok(Members{rows,page,total_pages:((count.max(0) as u64)+19)/20,q})
}
pub async fn set_limit(db:&DatabaseConnection,actor:&super::permissions::Actor,tenant:Uuid,max_members:i32)->Result<()>{
    if !(1..=100_000).contains(&max_members){return Err(Error::Invalid("invalid_member_limit"));}
    let txn=db.begin().await?;
    super::permissions::require_super(&txn,actor).await?;
    let changed=txn.execute_raw(Statement::from_sql_and_values(DbBackend::Postgres,
        "UPDATE tenants SET max_members=$2,updated_at=now() WHERE id=$1 AND kind='organization' AND status<>'deleted' AND max_members<>$2",
        [tenant.into(),max_members.into()])).await?.rows_affected();
    if changed==0 && get(&txn,tenant).await?.status=="deleted"{return Err(Error::Invalid("not_found"));}
    audit(&txn,actor.session.user_id,"tenant.member_limit.updated",tenant).await?;
    txn.commit().await?;
    Ok(())
}
pub async fn promote_owner(db:&DatabaseConnection,actor:&super::permissions::Actor,tenant:Uuid,user:Uuid)->Result<()>{
    let txn=db.begin().await?;
    super::permissions::require_super(&txn,actor).await?;
    txn.query_one_raw(Statement::from_sql_and_values(DbBackend::Postgres,
        "SELECT id FROM tenants WHERE id=$1 AND kind='organization' AND status<>'deleted' FOR UPDATE",
        [tenant.into()])).await?.ok_or(Error::Invalid("not_found"))?;
    let changed=txn.execute_raw(Statement::from_sql_and_values(DbBackend::Postgres,
        "UPDATE tenant_members m SET role='owner',auth_version=auth_version+1,updated_at=now() FROM users u WHERE m.tenant_id=$1 AND m.user_id=$2 AND u.id=m.user_id AND u.status='active' AND u.deleted_at IS NULL AND m.status='active' AND m.role<>'owner'",
        [tenant.into(),user.into()])).await?.rows_affected();
    if changed==0 && !txn.query_one_raw(Statement::from_sql_and_values(DbBackend::Postgres,
        "SELECT 1 FROM tenant_members m JOIN users u ON u.id=m.user_id WHERE m.tenant_id=$1 AND m.user_id=$2 AND m.status='active' AND m.role='owner' AND u.status='active' AND u.deleted_at IS NULL",
        [tenant.into(),user.into()])).await?.is_some(){return Err(Error::Invalid("not_found"));}
    audit(&txn,actor.session.user_id,"tenant.owner.recovered",tenant).await?;
    txn.commit().await?;
    Ok(())
}
async fn audit<C:ConnectionTrait>(db:&C,actor:Uuid,action:&str,tenant:Uuid)->Result<()>{
    db.execute_raw(Statement::from_sql_and_values(DbBackend::Postgres,
        "INSERT INTO audit_events(actor_id,actor_username,action,target,outcome,http_status) SELECT id,username,$2,$3,'success',200 FROM users WHERE id=$1",
        [actor.into(),action.into(),tenant.to_string().into()])).await?;
    Ok(())
}

#[derive(FromQueryResult,Serialize)]
pub struct AppAccess {
    pub id:Uuid,
    pub name:String,
    pub code:String,
    pub status:String,
    pub organization_access:String,
    pub granted:bool,
}
pub async fn apps<C:ConnectionTrait>(db:&C,tenant:Uuid)->Result<Vec<AppAccess>> {
    Ok(AppAccess::find_by_statement(Statement::from_sql_and_values(DbBackend::Postgres,
        "SELECT a.id,a.name,a.code::text,a.status::text,a.organization_access,EXISTS(SELECT 1 FROM tenant_app_grants g WHERE g.tenant_id=$1 AND g.app_id=a.id) AS granted FROM apps a WHERE NOT a.system AND a.tenant_mode IN ('organization','both') ORDER BY a.name,a.id",
        [tenant.into()])).all(db).await?)
}

/// The grant is organizational admission only. Changing it advances this tenant's
/// authorization epoch so a previously revoked grant cannot revive old JWTs.
pub async fn set_app_grant(db:&DatabaseConnection,actor:&super::permissions::Actor,tenant:Uuid,app:Uuid,allow:bool)->Result<()> {
    let txn=db.begin().await?;
    super::permissions::require_super(&txn,actor).await?;
    txn.query_one_raw(Statement::from_sql_and_values(DbBackend::Postgres,
        "SELECT id FROM apps WHERE id=$1 AND NOT system AND tenant_mode IN ('organization','both') FOR SHARE",
        [app.into()])).await?.ok_or(Error::Invalid("invalid_app"))?;
    txn.query_one_raw(Statement::from_sql_and_values(DbBackend::Postgres,
        "SELECT id FROM tenants WHERE id=$1 AND kind='organization' AND status<>'deleted' FOR UPDATE",
        [tenant.into()])).await?.ok_or(Error::Invalid("not_found"))?;
    let changed=if allow {
        txn.execute_raw(Statement::from_sql_and_values(DbBackend::Postgres,
            "INSERT INTO tenant_app_grants(tenant_id,app_id) VALUES($1,$2) ON CONFLICT DO NOTHING",
            [tenant.into(),app.into()])).await?.rows_affected()
    } else {
        txn.execute_raw(Statement::from_sql_and_values(DbBackend::Postgres,
            "DELETE FROM tenant_app_grants WHERE tenant_id=$1 AND app_id=$2",
            [tenant.into(),app.into()])).await?.rows_affected()
    };
    if changed>0 {
        txn.execute_raw(Statement::from_sql_and_values(DbBackend::Postgres,
            "UPDATE tenants SET auth_version=auth_version+1,updated_at=now() WHERE id=$1",
            [tenant.into()])).await?;
        txn.execute_raw(Statement::from_sql_and_values(DbBackend::Postgres,
            "UPDATE refresh_tokens SET revoked_at=now(),revoke_reason='tenant_app_admission_changed' WHERE tenant_id=$1 AND app_id=$2 AND revoked_at IS NULL",
            [tenant.into(),app.into()])).await?;
        txn.execute_raw(Statement::from_sql_and_values(DbBackend::Postgres,
            "DELETE FROM authorization_codes WHERE tenant_id=$1 AND app_id=$2 AND consumed_at IS NULL",
            [tenant.into(),app.into()])).await?;
    }
    audit(&txn,actor.session.user_id,if allow{"tenant.app.granted"}else{"tenant.app.revoked"},tenant).await?;
    txn.commit().await?;
    Ok(())
}
