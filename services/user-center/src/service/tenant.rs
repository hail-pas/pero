//! Basic organization governance. Business roles and data remain application-owned.
use super::ManagementError as Error;
use sea_orm::{
    ConnectionTrait, DatabaseConnection, DbBackend, DbErr, FromQueryResult, Statement,
    TransactionTrait,
};
use serde::Serialize;
use uuid::Uuid;
type Result<T> = std::result::Result<T, Error>;

#[derive(FromQueryResult, Serialize)]
pub struct Tenant {
    pub id: Uuid,
    pub kind: String,
    pub name: String,
    pub slug: Option<String>,
    pub status: String,
    pub role: String,
}
#[derive(FromQueryResult, Serialize)]
pub struct Member {
    pub user_id: Uuid,
    pub username: String,
    pub name: String,
    pub role: String,
    pub status: String,
}
#[derive(FromQueryResult, Serialize)]
pub struct Invitation {
    pub id: Uuid,
    pub email: String,
    pub role: String,
    pub status: String,
    pub expires_at: time::OffsetDateTime,
}
async fn exec<C: ConnectionTrait>(
    db: &C,
    sql: &str,
    args: Vec<sea_orm::Value>,
) -> std::result::Result<u64, DbErr> {
    Ok(db
        .execute_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            sql,
            args,
        ))
        .await?
        .rows_affected())
}
async fn audit<C: ConnectionTrait>(
    db: &C,
    actor: Uuid,
    action: &str,
    target: &str,
) -> std::result::Result<(), DbErr> {
    exec(
        db,
        "INSERT INTO audit_events(actor_id,actor_username,action,target,outcome,http_status) SELECT id,username,$2,$3,'success',200 FROM users WHERE id=$1",
        vec![actor.into(), action.into(), target.into()],
    )
    .await?;
    Ok(())
}
pub async fn list<C: ConnectionTrait>(db: &C, user: Uuid) -> Result<Vec<Tenant>> {
    Ok(Tenant::find_by_statement(Statement::from_sql_and_values(DbBackend::Postgres,
        "SELECT t.id,t.kind,t.name,t.slug::text,t.status,m.role FROM tenants t JOIN tenant_members m ON m.tenant_id=t.id WHERE m.user_id=$1 AND m.status='active' ORDER BY (t.kind='personal') DESC,t.name",
        [user.into()])).all(db).await?)
}
pub async fn get<C: ConnectionTrait>(db: &C, user: Uuid, id: Uuid) -> Result<Tenant> {
    Tenant::find_by_statement(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "SELECT t.id,t.kind,t.name,t.slug::text,t.status,m.role FROM tenants t JOIN tenant_members m ON m.tenant_id=t.id WHERE t.id=$1 AND m.user_id=$2 AND m.status='active'",
        [id.into(), user.into()],
    ))
    .one(db)
    .await?
    .ok_or(Error::Invalid("not_found"))
}
pub async fn members<C: ConnectionTrait>(db: &C, user: Uuid, id: Uuid) -> Result<Vec<Member>> {
    let t = get(db, user, id).await?;
    if t.kind != "organization" {
        return Err(Error::Invalid("forbidden"));
    }
    Ok(Member::find_by_statement(Statement::from_sql_and_values(DbBackend::Postgres,
        "SELECT m.user_id,u.username::text,COALESCE(u.nickname,u.username::text) AS name,m.role,m.status FROM tenant_members m JOIN users u ON u.id=m.user_id WHERE m.tenant_id=$1 AND m.status='active' ORDER BY (m.role='owner') DESC,m.joined_at",
        [id.into()])).all(db).await?)
}
pub async fn invitations<C: ConnectionTrait>(
    db: &C,
    user: Uuid,
    id: Uuid,
) -> Result<Vec<Invitation>> {
    governance(db, user, id).await?;
    Ok(Invitation::find_by_statement(Statement::from_sql_and_values(DbBackend::Postgres,
        "SELECT id,email::text,role,status,expires_at FROM tenant_invitations WHERE tenant_id=$1 ORDER BY created_at DESC LIMIT 100",[id.into()])).all(db).await?)
}
async fn governance<C: ConnectionTrait>(db: &C, user: Uuid, id: Uuid) -> Result<String> {
    let t = get(db, user, id).await?;
    if t.kind != "organization" || !matches!(t.role.as_str(), "owner" | "admin") {
        return Err(Error::Invalid("forbidden"));
    }
    Ok(t.role)
}

/// Governance mutations lock the organization before checking roles. This prevents
/// a concurrent removal or demotion from authorizing a later privileged write.
async fn lock_organization<C: ConnectionTrait>(db: &C, id: Uuid) -> Result<()> {
    db.query_one_raw(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "SELECT id FROM tenants WHERE id=$1 AND kind='organization' FOR UPDATE",
        [id.into()],
    ))
    .await?
    .ok_or(Error::Invalid("not_found"))?;
    Ok(())
}
pub async fn create(db: &DatabaseConnection, user: Uuid, name: &str, slug: &str) -> Result<()> {
    let name = name.trim();
    let slug = slug.trim().to_lowercase();
    if name.is_empty()
        || name.chars().count() > 100
        || slug.len() < 3
        || slug.len() > 64
        || !slug
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err(Error::Invalid("invalid_request"));
    }
    let txn = db.begin().await?;
    let verified = txn.query_one_raw(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "SELECT id FROM users WHERE id=$1 AND status='active' AND deleted_at IS NULL AND (email_verified_at IS NOT NULL OR phone_verified_at IS NOT NULL)",
        [user.into()],
    )).await?.is_some();
    if !verified {
        return Err(Error::Invalid("tenant_verified_contact_required"));
    }
    let row = txn
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "INSERT INTO tenants(kind,name,slug) VALUES('organization',$1,$2) RETURNING id",
            [name.into(), slug.into()],
        ))
        .await
        .map_err(|error| {
            if crate::db::error::is_unique_violation(&error) {
                Error::Invalid("tenant_slug_exists")
            } else {
                error.into()
            }
        })?
        .ok_or(Error::Invalid("update_failed"))?;
    let id: Uuid = row.try_get("", "id")?;
    exec(
        &txn,
        "INSERT INTO tenant_members(tenant_id,user_id,role) VALUES($1,$2,'owner')",
        vec![id.into(), user.into()],
    )
    .await?;
    audit(&txn, user, "tenant.created", &id.to_string()).await?;
    txn.commit().await?;
    Ok(())
}
pub async fn rename(db: &DatabaseConnection, user: Uuid, id: Uuid, name: &str) -> Result<()> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > 100 {
        return Err(Error::Invalid("invalid_request"));
    }
    let txn = db.begin().await?;
    lock_organization(&txn, id).await?;
    governance(&txn, user, id).await?;
    exec(
        &txn,
        "UPDATE tenants SET name=$2,updated_at=now() WHERE id=$1 AND kind='organization'",
        vec![id.into(), name.into()],
    )
    .await?;
    audit(&txn, user, "tenant.renamed", &id.to_string()).await?;
    txn.commit().await?;
    Ok(())
}
pub async fn update_member(
    db: &DatabaseConnection,
    actor: Uuid,
    tenant: Uuid,
    target: Uuid,
    action: &str,
) -> Result<()> {
    if !matches!(action, "owner" | "admin" | "member" | "remove") {
        return Err(Error::Invalid("invalid_request"));
    }
    let txn = db.begin().await?;
    // Serialize role changes and the last-owner check on the tenant row.
    lock_organization(&txn, tenant).await?;
    let actor_role = if action == "remove" && actor == target {
        let space = get(&txn, actor, tenant).await?;
        if space.kind != "organization" {
            return Err(Error::Invalid("forbidden"));
        }
        space.role
    } else {
        governance(&txn, actor, tenant).await?
    };
    let current = txn
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT role,status FROM tenant_members WHERE tenant_id=$1 AND user_id=$2 FOR UPDATE",
            [tenant.into(), target.into()],
        ))
        .await?
        .ok_or(Error::Invalid("not_found"))?;
    let role: String = current.try_get("", "role")?;
    let status: String = current.try_get("", "status")?;
    if status != "active"
        || (role == "owner" && actor_role != "owner")
        || (action == "owner" && actor_role != "owner")
        || (actor != target && actor_role == "admin" && (role != "member" || action != "remove"))
        || (actor == target && action != "remove" && actor_role != "owner")
    {
        return Err(Error::Invalid("forbidden"));
    }
    if role == "owner" && action != "owner" {
        let row=txn.query_one_raw(Statement::from_sql_and_values(DbBackend::Postgres,
            "SELECT count(*)::bigint AS n FROM tenant_members WHERE tenant_id=$1 AND role='owner' AND status='active'",[tenant.into()])).await?.ok_or(Error::Invalid("not_found"))?;
        let count: i64 = row.try_get("", "n")?;
        if count <= 1 {
            return Err(Error::Invalid("last_tenant_owner"));
        }
    }
    if action == "remove" {
        exec(&txn,"UPDATE tenant_members SET status='removed',auth_version=auth_version+1,updated_at=now() WHERE tenant_id=$1 AND user_id=$2",vec![tenant.into(),target.into()]).await?;
        exec(&txn,"UPDATE refresh_tokens SET revoked_at=now(),revoke_reason='tenant_member_removed' WHERE tenant_id=$1 AND user_id=$2 AND revoked_at IS NULL",vec![tenant.into(),target.into()]).await?;
        exec(&txn,"UPDATE authorization_codes SET consumed_at=now() WHERE tenant_id=$1 AND user_id=$2 AND consumed_at IS NULL",vec![tenant.into(),target.into()]).await?;
    } else {
        exec(
            &txn,
            "UPDATE tenant_members SET role=$3,auth_version=auth_version+1,updated_at=now() WHERE tenant_id=$1 AND user_id=$2 AND role<>$3",
            vec![tenant.into(), target.into(), action.into()],
        )
        .await?;
    }
    audit(
        &txn,
        actor,
        &format!("tenant.member.{action}"),
        &format!("{tenant}/{target}"),
    )
    .await?;
    txn.commit().await?;
    Ok(())
}
pub async fn leave(db: &DatabaseConnection, user: Uuid, tenant: Uuid) -> Result<()> {
    update_member(db, user, tenant, user, "remove").await
}
pub async fn invite(
    state: &crate::state::app::AppState,
    user: Uuid,
    id: Uuid,
    email: &str,
    role: &str,
) -> Result<()> {
    let email = email.trim().to_lowercase();
    if !matches!(role, "admin" | "member")
        || email.len() > 254
        || !validator::ValidateEmail::validate_email(&email)
    {
        return Err(Error::Invalid("invalid_request"));
    }
    if !state.config.notification.available("email") {
        return Err(Error::Invalid("notification_disabled"));
    }
    let txn = state.db.begin().await?;
    lock_organization(&txn, id).await?;
    let actor_role = governance(&txn, user, id).await?;
    if role == "admin" && actor_role != "owner" {
        return Err(Error::Invalid("forbidden"));
    }
    let token = pero_utils::crypto::generate_token();
    let hash = pero_utils::crypto::sha256_hex(&token);
    let expiry = time::OffsetDateTime::now_utc() + time::Duration::days(7);
    exec(&txn,"UPDATE tenant_invitations SET status='revoked' WHERE tenant_id=$1 AND email=$2 AND status='pending'",vec![id.into(),email.clone().into()]).await?;
    exec(&txn,"INSERT INTO tenant_invitations(tenant_id,email,role,token_hash,invited_by,expires_at) VALUES($1,$2,$3,$4,$5,$6)",vec![id.into(),email.clone().into(),role.into(),hash.into(),user.into(),expiry.into()]).await?;
    let mut link =
        pero_utils::oauth::url::issuer_endpoint(&state.config.oidc.issuer, "account/invitations");
    link.push('/');
    link.push_str(&token);
    super::notify::enqueue(
        &txn,
        user,
        &super::notify::Notification {
            channel: "email",
            kind: "tenant_invitation",
            to: &email,
            code: None,
            link: &link,
        },
        expiry,
    )
    .await?;
    audit(&txn, user, "tenant.invitation.created", &id.to_string()).await?;
    txn.commit().await?;
    Ok(())
}
pub async fn revoke_invite(
    db: &DatabaseConnection,
    user: Uuid,
    tenant: Uuid,
    invitation: Uuid,
) -> Result<()> {
    let txn = db.begin().await?;
    lock_organization(&txn, tenant).await?;
    governance(&txn, user, tenant).await?;
    if exec(&txn,"UPDATE tenant_invitations SET status='revoked' WHERE id=$1 AND tenant_id=$2 AND status='pending'",vec![invitation.into(),tenant.into()]).await?!=1{return Err(Error::Invalid("not_found"));}
    audit(
        &txn,
        user,
        "tenant.invitation.revoked",
        &format!("{tenant}/{invitation}"),
    )
    .await?;
    txn.commit().await?;
    Ok(())
}
#[derive(FromQueryResult, Serialize)]
pub struct InviteDetail {
    pub tenant_id: Uuid,
    pub tenant_name: String,
    pub email: String,
    pub role: String,
}
pub async fn invitation<C: ConnectionTrait>(db: &C, token: &str) -> Result<InviteDetail> {
    let hash = pero_utils::crypto::sha256_hex(token);
    InviteDetail::find_by_statement(Statement::from_sql_and_values(DbBackend::Postgres,
        "SELECT i.tenant_id,t.name AS tenant_name,i.email::text,i.role FROM tenant_invitations i JOIN tenants t ON t.id=i.tenant_id WHERE i.token_hash=$1 AND i.status='pending' AND i.expires_at>now() AND t.status='active'",
        [hash.into()])).one(db).await?.ok_or(Error::Invalid("not_found"))
}
pub async fn accept(db: &DatabaseConnection, user: Uuid, token: &str) -> Result<()> {
    let txn = db.begin().await?;
    let hash = pero_utils::crypto::sha256_hex(token);
    let invitation = txn
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT tenant_id FROM tenant_invitations WHERE token_hash=$1",
            [hash.clone().into()],
        ))
        .await?
        .ok_or(Error::Invalid("invalid_invitation"))?;
    let tenant: Uuid = invitation.try_get("", "tenant_id")?;
    // Match governance's tenant -> invitation/member lock order.
    lock_organization(&txn, tenant).await?;
    let row=txn.query_one_raw(Statement::from_sql_and_values(DbBackend::Postgres,
        "SELECT i.id,i.tenant_id,i.role,i.status FROM tenant_invitations i JOIN tenants t ON t.id=i.tenant_id JOIN users u ON u.id=$2 WHERE i.token_hash=$1 AND i.status IN ('pending','accepted') AND (i.expires_at>now() OR i.status='accepted') AND t.status='active' AND t.kind='organization' AND u.email=i.email AND u.email_verified_at IS NOT NULL AND u.status='active' AND u.deleted_at IS NULL FOR UPDATE OF i",
        [hash.into(),user.into()])).await?.ok_or(Error::Invalid("invalid_invitation"))?;
    let id: Uuid = row.try_get("", "id")?;
    let role: String = row.try_get("", "role")?;
    let status: String = row.try_get("", "status")?;
    if status == "accepted" {
        let joined = txn.query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT user_id FROM tenant_members WHERE tenant_id=$1 AND user_id=$2 AND status='active'",
            [tenant.into(), user.into()],
        )).await?.is_some();
        return if joined {
            Ok(())
        } else {
            Err(Error::Invalid("invalid_invitation"))
        };
    }
    exec(&txn,"INSERT INTO tenant_members(tenant_id,user_id,role) VALUES($1,$2,$3) ON CONFLICT(tenant_id,user_id) DO UPDATE SET role=CASE WHEN tenant_members.status='active' THEN tenant_members.role ELSE EXCLUDED.role END,status='active',auth_version=tenant_members.auth_version+1,updated_at=now()",vec![tenant.into(),user.into(),role.into()]).await?;
    exec(
        &txn,
        "UPDATE tenant_invitations SET status='accepted',accepted_at=now() WHERE id=$1",
        vec![id.into()],
    )
    .await?;
    audit(
        &txn,
        user,
        "tenant.invitation.accepted",
        &tenant.to_string(),
    )
    .await?;
    txn.commit().await?;
    Ok(())
}

pub async fn toggle_status(
    db: &DatabaseConnection,
    actor: Uuid,
    tenant: Uuid,
    platform_super_admin: bool,
) -> Result<()> {
    let txn = db.begin().await?;
    lock_organization(&txn, tenant).await?;
    if !platform_super_admin {
        let space = get(&txn, actor, tenant).await?;
        if space.kind != "organization" || space.role != "owner" {
            return Err(Error::Invalid("forbidden"));
        }
    }
    let changed = exec(
        &txn,
        "UPDATE tenants SET status=CASE status WHEN 'active' THEN 'disabled' ELSE 'active' END,auth_version=auth_version+1,updated_at=now() WHERE id=$1 AND kind='organization'",
        vec![tenant.into()],
    )
    .await?;
    if changed != 1 {
        return Err(Error::Invalid("not_found"));
    }
    exec(
        &txn,
        "UPDATE refresh_tokens SET revoked_at=now(),revoke_reason='tenant_status_changed' WHERE tenant_id=$1 AND revoked_at IS NULL",
        vec![tenant.into()],
    )
    .await?;
    exec(
        &txn,
        "UPDATE authorization_codes SET consumed_at=now() WHERE tenant_id=$1 AND consumed_at IS NULL",
        vec![tenant.into()],
    )
    .await?;
    audit(&txn, actor, "tenant.status.toggled", &tenant.to_string()).await?;
    txn.commit().await?;
    Ok(())
}
