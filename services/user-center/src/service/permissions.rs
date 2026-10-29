//! Fixed permission catalog and explicit application grants. Always read from the primary DB.
use super::{ManagementError, security as sec};
use sea_orm::{
    ColumnTrait, ConnectionTrait, DbBackend, EntityTrait, FromQueryResult, QueryFilter,
    QuerySelect, Statement, TransactionTrait,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Permission {
    #[serde(rename = "users.read")]
    UsersRead,
    #[serde(rename = "users.sensitive.read")]
    UsersSensitiveRead,
    #[serde(rename = "users.create")]
    UsersCreate,
    #[serde(rename = "users.update")]
    UsersUpdate,
    #[serde(rename = "users.contact.update")]
    UsersContactUpdate,
    #[serde(rename = "users.status.update")]
    UsersStatusUpdate,
    #[serde(rename = "users.password.reset")]
    UsersPasswordReset,
    #[serde(rename = "apps.read")]
    AppsRead,
    #[serde(rename = "apps.manage")]
    AppsManage,
    #[serde(rename = "clients.read")]
    ClientsRead,
    #[serde(rename = "clients.manage")]
    ClientsManage,
    #[serde(rename = "clients.secret.rotate")]
    ClientsSecretRotate,
    #[serde(rename = "apps.members.read")]
    AppsMembersRead,
    #[serde(rename = "apps.members.manage")]
    AppsMembersManage,
    #[serde(rename = "providers.read")]
    ProvidersRead,
    #[serde(rename = "events.read")]
    EventsRead,
    #[serde(rename = "audit.read")]
    AuditRead,
    #[serde(rename = "notifications.read")]
    NotificationsRead,
    #[serde(rename = "notifications.retry")]
    NotificationsRetry,
}
impl Permission {
    pub fn code(self) -> &'static str {
        match self {
            Self::UsersRead => "users.read",
            Self::UsersSensitiveRead => "users.sensitive.read",
            Self::UsersCreate => "users.create",
            Self::UsersUpdate => "users.update",
            Self::UsersContactUpdate => "users.contact.update",
            Self::UsersStatusUpdate => "users.status.update",
            Self::UsersPasswordReset => "users.password.reset",
            Self::AppsRead => "apps.read",
            Self::AppsManage => "apps.manage",
            Self::ClientsRead => "clients.read",
            Self::ClientsManage => "clients.manage",
            Self::ClientsSecretRotate => "clients.secret.rotate",
            Self::AppsMembersRead => "apps.members.read",
            Self::AppsMembersManage => "apps.members.manage",
            Self::ProvidersRead => "providers.read",
            Self::EventsRead => "events.read",
            Self::AuditRead => "audit.read",
            Self::NotificationsRead => "notifications.read",
            Self::NotificationsRetry => "notifications.retry",
        }
    }
    pub fn is_app(self) -> bool {
        matches!(
            self,
            Self::AppsRead
                | Self::AppsManage
                | Self::ClientsRead
                | Self::ClientsManage
                | Self::ClientsSecretRotate
                | Self::AppsMembersRead
                | Self::AppsMembersManage
        )
    }
    pub fn dependencies(self) -> &'static [Self] {
        match self {
            Self::UsersRead => &[],
            Self::UsersSensitiveRead => &[Self::UsersRead],
            Self::UsersCreate => &[Self::UsersRead],
            Self::UsersUpdate => &[Self::UsersRead],
            Self::UsersContactUpdate => &[Self::UsersRead, Self::UsersSensitiveRead],
            Self::UsersStatusUpdate => &[Self::UsersRead],
            Self::UsersPasswordReset => &[Self::UsersRead],
            Self::AppsRead => &[],
            Self::AppsManage => &[Self::AppsRead],
            Self::ClientsRead => &[Self::AppsRead],
            Self::ClientsManage => &[Self::ClientsRead],
            Self::ClientsSecretRotate => &[Self::ClientsRead],
            Self::AppsMembersRead => &[Self::AppsRead],
            Self::AppsMembersManage => &[Self::AppsMembersRead],
            Self::ProvidersRead => &[],
            Self::EventsRead => &[],
            Self::AuditRead => &[],
            Self::NotificationsRead => &[],
            Self::NotificationsRetry => &[Self::NotificationsRead],
        }
    }
}
pub fn catalog() -> serde_json::Value {
    use Permission::*;
    let definitions = [
        (UsersRead, "用户查询", ""),
        (UsersSensitiveRead, "完整联系方式", ""),
        (UsersCreate, "创建用户", ""),
        (UsersUpdate, "修改资料", ""),
        (UsersContactUpdate, "修改联系方式", ""),
        (UsersStatusUpdate, "启停账户", ""),
        (UsersPasswordReset, "重置密码", ""),
        (AppsRead, "应用查询", ""),
        (AppsManage, "应用管理", "高影响：可编辑应用资料及启停应用"),
        (ClientsRead, "客户端查询", ""),
        (
            ClientsManage,
            "客户端管理",
            "高影响：可修改登录回调、scope、类型及创建客户端密钥",
        ),
        (ClientsSecretRotate, "客户端密钥轮换", ""),
        (AppsMembersRead, "成员查询", ""),
        (AppsMembersManage, "成员管理", ""),
        (ProvidersRead, "提供方摘要", ""),
        (EventsRead, "全局登录记录", "包含 IP 等全局敏感元数据"),
        (AuditRead, "全局操作审计", ""),
        (NotificationsRead, "通知记录", ""),
        (NotificationsRetry, "重试通知", ""),
    ];
    serde_json::Value::Array(definitions.into_iter().map(|(permission,name,risk)|serde_json::json!({"code":permission,"scope":if permission.is_app(){"app"}else{"global"},"group":permission.code().split('.').next(),"name":name,"risk":risk,"dependencies":permission.dependencies()})).collect())
}
#[derive(Debug, Clone, Default, Serialize)]
pub struct Grants {
    pub revision: i64,
    pub global_permissions: BTreeSet<Permission>,
    pub app_grants: BTreeMap<Uuid, BTreeSet<Permission>>,
}
#[derive(Debug, Clone, Default, Serialize)]
pub struct Access {
    pub super_admin: bool,
    #[serde(flatten)]
    pub grants: Grants,
}
impl Access {
    pub fn can_global(&self, p: Permission) -> bool {
        !p.is_app() && (self.super_admin || self.grants.global_permissions.contains(&p))
    }
    pub fn can_app(&self, id: Uuid, p: Permission) -> bool {
        p.is_app()
            && (self.super_admin
                || self
                    .grants
                    .app_grants
                    .get(&id)
                    .is_some_and(|s| s.contains(&p)))
    }
    pub fn app_ids(&self, p: Permission) -> Vec<Uuid> {
        self.grants
            .app_grants
            .iter()
            .filter(|(_, s)| s.contains(&p))
            .map(|(id, _)| *id)
            .collect()
    }
    pub fn require_global(&self, p: Permission) -> Result<(), ManagementError> {
        if self.can_global(p) {
            Ok(())
        } else {
            Err(ManagementError::Invalid("forbidden"))
        }
    }
    pub fn require_app(&self, id: Uuid, p: Permission) -> Result<(), ManagementError> {
        if !self.can_app(id, Permission::AppsRead) {
            return Err(ManagementError::Invalid("not_found"));
        }
        if self.can_app(id, p) {
            Ok(())
        } else {
            Err(ManagementError::Invalid("forbidden"))
        }
    }
}
#[derive(FromQueryResult)]
struct Revision {
    revision: i64,
}
#[derive(FromQueryResult)]
struct GlobalRow {
    permission: String,
}
#[derive(FromQueryResult)]
struct AppRow {
    app_id: Uuid,
    permission: String,
}
fn parse(code: String) -> Result<Permission, ManagementError> {
    serde_json::from_value(serde_json::Value::String(code))
        .map_err(|_| ManagementError::Invalid("forbidden"))
}
pub async fn load<C: ConnectionTrait>(db: &C, user: Uuid) -> Result<Access, ManagementError> {
    let role = sec::role(db, user).await?;
    if role.as_deref() == Some("super_admin") {
        return Ok(Access {
            super_admin: true,
            ..Default::default()
        });
    }
    if role.as_deref() != Some("admin") {
        return Err(ManagementError::Invalid("forbidden"));
    }
    let revision = Revision::find_by_statement(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "SELECT revision FROM admin_permission_state WHERE user_id=$1",
        [user.into()],
    ))
    .one(db)
    .await?
    .ok_or(ManagementError::Invalid("forbidden"))?
    .revision;
    let mut grants = Grants {
        revision,
        ..Default::default()
    };
    for row in GlobalRow::find_by_statement(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "SELECT permission FROM admin_permissions WHERE user_id=$1",
        [user.into()],
    ))
    .all(db)
    .await?
    {
        let p = parse(row.permission)?;
        if p.is_app() {
            return Err(ManagementError::Invalid("forbidden"));
        }
        grants.global_permissions.insert(p);
    }
    for row in AppRow::find_by_statement(Statement::from_sql_and_values(DbBackend::Postgres,"SELECT g.app_id,g.permission FROM admin_app_permissions g JOIN apps a ON a.id=g.app_id WHERE g.user_id=$1 AND NOT a.system",[user.into()])).all(db).await? {
  let p=parse(row.permission)?; if !p.is_app(){return Err(ManagementError::Invalid("forbidden"));} grants.app_grants.entry(row.app_id).or_default().insert(p);
 }
    validate(&grants)?;
    Ok(Access {
        super_admin: false,
        grants,
    })
}
fn validate(g: &Grants) -> Result<(), ManagementError> {
    for (set, app) in std::iter::once((&g.global_permissions, false))
        .chain(g.app_grants.values().map(|s| (s, true)))
    {
        for p in set {
            if p.is_app() != app || p.dependencies().iter().any(|d| !set.contains(d)) {
                return Err(ManagementError::Invalid("invalid_permission_dependencies"));
            }
        }
    }
    Ok(())
}
/// A trusted session supplied by the dashboard extractor, never deserialized from input.
#[derive(Clone)]
pub struct Actor {
    pub session: crate::state::session::SsoSession,
    pub idle_ttl_seconds: u64,
}
pub async fn authorize(
    db: &sea_orm::DatabaseTransaction,
    actor: &Actor,
) -> Result<Access, ManagementError> {
    super::admin::lock_policy(db).await?;
    // Protect the actor from credential/status changes without blocking token
    // issuance, which locks app/access rows before taking a shared user lock.
    let user = crate::db::entity::users::Entity::find_by_id(actor.session.user_id)
        .filter(crate::db::entity::users::Column::DeletedAt.is_null())
        .lock_shared()
        .one(db)
        .await?
        .ok_or(ManagementError::Invalid("forbidden"))?;
    if user.status != crate::db::enums::UserStatus::Active
        || user.deleted_at.is_some()
        || !sec::mfa_enabled(db, user.id).await?
        || !sec::recent(db, actor.session.id, actor.idle_ttl_seconds).await?
    {
        return Err(ManagementError::Invalid("forbidden"));
    }
    // recent() validates expiry/revocation; bind its row to this user and require MFA assurance.
    let session = crate::db::entity::sso_sessions::Entity::find_by_id(actor.session.id)
        .one(db)
        .await?
        .ok_or(ManagementError::Invalid("forbidden"))?;
    if session.user_id != user.id || session.mfa_verified_at.is_none() {
        return Err(ManagementError::Invalid("forbidden"));
    }
    load(db, user.id).await
}
pub async fn require_super(
    db: &sea_orm::DatabaseTransaction,
    actor: &Actor,
) -> Result<(), ManagementError> {
    if !authorize(db, actor).await?.super_admin {
        return Err(ManagementError::Invalid("forbidden"));
    }
    Ok(())
}
pub async fn protect_user<C: ConnectionTrait>(
    db: &C,
    access: &Access,
    id: Uuid,
) -> Result<(), ManagementError> {
    if !access.super_admin && sec::role(db, id).await?.is_some() {
        return Err(ManagementError::Invalid("not_found"));
    }
    Ok(())
}
pub async fn app<C: ConnectionTrait>(
    db: &C,
    access: &Access,
    id: Uuid,
    p: Permission,
) -> Result<(), ManagementError> {
    let a = crate::db::entity::apps::Entity::find_by_id(id)
        .one(db)
        .await?
        .ok_or(ManagementError::Invalid("not_found"))?;
    if a.system && !access.super_admin {
        return Err(ManagementError::Invalid("not_found"));
    }
    access.require_app(id, p)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantInput {
    pub app_id: Uuid,
    pub permissions: BTreeSet<Permission>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Replace {
    pub revision: i64,
    pub global_permissions: BTreeSet<Permission>,
    pub app_grants: Vec<GrantInput>,
    pub csrf_token: String,
}
pub async fn replace(
    db: &sea_orm::DatabaseConnection,
    actor: &Actor,
    target: Uuid,
    input: Replace,
    audit_id: Uuid,
) -> Result<(), ManagementError> {
    let txn = db.begin().await?;
    let access = authorize(&txn, actor).await?;
    if !access.super_admin {
        return Err(ManagementError::Invalid("forbidden"));
    }
    let user = super::password::PasswordIdentityService::lock_user(&txn, target).await?;
    if user.status != crate::db::enums::UserStatus::Active
        || user.deleted_at.is_some()
        || sec::role(&txn, target).await?.as_deref() != Some("admin")
    {
        return Err(ManagementError::Invalid("not_found"));
    }
    let before = load(&txn, target).await?.grants;
    if before.revision != input.revision {
        return Err(ManagementError::Invalid("permission_revision_conflict"));
    }
    let mut after = Grants {
        revision: before.revision + 1,
        global_permissions: input.global_permissions,
        ..Default::default()
    };
    for grant in input.app_grants {
        let a = crate::db::entity::apps::Entity::find_by_id(grant.app_id)
            .one(&txn)
            .await?
            .ok_or(ManagementError::Invalid("not_found"))?;
        if a.system
            || grant.permissions.is_empty()
            || after
                .app_grants
                .insert(grant.app_id, grant.permissions)
                .is_some()
        {
            return Err(ManagementError::Invalid("invalid_request"));
        }
    }
    validate(&after)?;
    if before.global_permissions == after.global_permissions
        && before.app_grants == after.app_grants
    {
        return Ok(());
    }
    sec::execute(
        &txn,
        "DELETE FROM admin_permissions WHERE user_id=$1",
        vec![target.into()],
    )
    .await?;
    sec::execute(
        &txn,
        "DELETE FROM admin_app_permissions WHERE user_id=$1",
        vec![target.into()],
    )
    .await?;
    for p in &after.global_permissions {
        sec::execute(
            &txn,
            "INSERT INTO admin_permissions(user_id,permission) VALUES($1,$2)",
            vec![target.into(), p.code().into()],
        )
        .await?;
    }
    for (id, set) in &after.app_grants {
        for p in set {
            sec::execute(
                &txn,
                "INSERT INTO admin_app_permissions(user_id,app_id,permission) VALUES($1,$2,$3)",
                vec![target.into(), (*id).into(), p.code().into()],
            )
            .await?;
        }
    }
    sec::execute(&txn,"UPDATE admin_permission_state SET revision=$2,updated_by=$3,updated_at=now() WHERE user_id=$1",vec![target.into(),after.revision.into(),actor.session.user_id.into()]).await?;
    fn entries(g: &Grants) -> BTreeSet<(Option<Uuid>, Permission)> {
        g.global_permissions
            .iter()
            .map(|p| (None, *p))
            .chain(
                g.app_grants
                    .iter()
                    .flat_map(|(id, s)| s.iter().map(move |p| (Some(*id), *p))),
            )
            .collect()
    }
    let old = entries(&before);
    let new = entries(&after);
    let diff = |items: Vec<&(Option<Uuid>, Permission)>| {
        items.into_iter().map(|(id,p)|serde_json::json!({"scope":if id.is_some(){"app"}else{"global"},"app_id":id,"permission":p})).collect::<Vec<_>>()
    };
    let details = serde_json::json!({"actor_id":actor.session.user_id,"target_id":target,"before_revision":before.revision,"after_revision":after.revision,"added":diff(new.difference(&old).collect()),"removed":diff(old.difference(&new).collect())});
    let updated=txn.execute_raw(Statement::from_sql_and_values(DbBackend::Postgres,"UPDATE audit_events SET details=$2,outcome='success',http_status=200 WHERE id=$1 AND actor_id=$3",[audit_id.into(),details.into(),actor.session.user_id.into()])).await?;
    if updated.rows_affected() != 1 {
        return Err(ManagementError::Dependency(sea_orm::DbErr::Custom(
            "Permission audit missing".into(),
        )));
    }
    super::session::SessionService::revoke_all_login_state_for_user_in_db(
        &txn,
        target,
        "admin_permissions_changed",
    )
    .await?;
    txn.commit().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dependencies_are_scoped_to_the_same_application() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let mut grants = Grants::default();
        grants.app_grants.insert(
            a,
            BTreeSet::from([Permission::AppsRead, Permission::ClientsRead]),
        );
        grants
            .app_grants
            .insert(b, BTreeSet::from([Permission::ClientsManage]));
        assert!(validate(&grants).is_err());
        grants.app_grants.insert(
            b,
            BTreeSet::from([
                Permission::AppsRead,
                Permission::ClientsRead,
                Permission::ClientsManage,
            ]),
        );
        assert!(validate(&grants).is_ok());
        grants.global_permissions.insert(Permission::ClientsManage);
        assert!(validate(&grants).is_err());
    }
}
