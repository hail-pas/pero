use super::permissions::{self, Actor, Permission as P};
// Application policy mutations hold the policy lock through grant revocation.
use super::ManagementError;
use crate::db::{entity::apps, enums::CommonStatus};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DatabaseConnection, DbBackend, EntityTrait,
    QueryFilter, QuerySelect, Set, Statement, TransactionTrait,
};

pub struct AppUpdate {
    pub name: String,
    pub description: Option<String>,
    pub homepage_url: Option<String>,
    pub logo_url: Option<String>,
    pub tenant_mode: String,
    pub organization_access: String,
    pub organization_auto_access: bool,
    pub max_sessions: i32,
}

impl AppUpdate {
    fn validate(&self) -> Result<(), ManagementError> {
        if self.max_sessions < 0 {
            return Err(ManagementError::Invalid("invalid_max_sessions"));
        }
        if !matches!(
            self.tenant_mode.as_str(),
            "personal" | "organization" | "both"
        ) {
            return Err(ManagementError::Invalid("invalid_tenant_mode"));
        }
        if !matches!(self.organization_access.as_str(), "open" | "restricted") {
            return Err(ManagementError::Invalid("invalid_organization_access"));
        }
        if self.name.trim().is_empty() {
            return Err(ManagementError::Invalid("name_required"));
        }
        for url in [&self.homepage_url, &self.logo_url].into_iter().flatten() {
            pero_utils::redirect::validate_public_http_url(url)
                .map_err(|_| ManagementError::Invalid("invalid_url"))?;
        }
        Ok(())
    }
    fn apply(self, active: &mut apps::ActiveModel) {
        active.max_sessions = Set(self.max_sessions);
        active.tenant_mode = Set(self.tenant_mode);
        active.organization_access = Set(self.organization_access);
        active.organization_auto_access = Set(self.organization_auto_access);
        active.name = Set(self.name);
        active.description = Set(self.description);
        active.homepage_url = Set(self.homepage_url);
        active.logo_url = Set(self.logo_url);
        active.updated_at = Set(time::OffsetDateTime::now_utc());
    }
}

pub async fn create(
    db: &DatabaseConnection,
    actor: &Actor,
    code: &str,
    input: AppUpdate,
) -> Result<(), ManagementError> {
    if code.is_empty() || input.name.is_empty() {
        return Err(ManagementError::Invalid("code_and_name_required"));
    }
    input.validate()?;
    let txn = db.begin().await?;
    let access = permissions::authorize(&txn, actor).await?;
    if !access.super_admin {
        return Err(ManagementError::Invalid("forbidden"));
    }

    if apps::Entity::find()
        .filter(apps::Column::Code.eq(code))
        .one(&txn)
        .await?
        .is_some()
    {
        return Err(ManagementError::Invalid("code_exists"));
    }
    let mut active = apps::ActiveModel {
        id: Set(uuid::Uuid::now_v7()),
        code: Set(code.to_owned()),
        system: Set(false),
        status: Set(CommonStatus::Active),
        created_at: Set(time::OffsetDateTime::now_utc()),
        ..Default::default()
    };
    input.apply(&mut active);
    active.insert(&txn).await.map_err(|error| {
        if crate::db::error::is_unique_violation(&error) {
            ManagementError::Invalid("code_exists")
        } else {
            error.into()
        }
    })?;
    txn.commit().await?;
    Ok(())
}

async fn editable(
    db: &sea_orm::DatabaseTransaction,
    id: uuid::Uuid,
) -> Result<apps::Model, ManagementError> {
    let app = apps::Entity::find_by_id(id)
        .lock_exclusive()
        .one(db)
        .await?
        .ok_or(ManagementError::Invalid("not_found"))?;
    if app.system {
        return Err(ManagementError::Invalid("system_app_protected"));
    }
    Ok(app)
}

pub async fn update(
    db: &DatabaseConnection,
    actor: &Actor,
    id: uuid::Uuid,
    input: AppUpdate,
    idle_ttl: u64,
) -> Result<(), ManagementError> {
    input.validate()?;
    let txn = db.begin().await?;
    let access = permissions::authorize(&txn, actor).await?;
    permissions::app(&txn, &access, id, P::AppsManage).await?;

    let old = editable(&txn, id).await?;
    if (old.tenant_mode != input.tenant_mode
        || old.organization_access != input.organization_access
        || old.organization_auto_access != input.organization_auto_access)
        && !access.super_admin
    {
        return Err(ManagementError::Invalid("forbidden"));
    }
    let changed = old.tenant_mode != input.tenant_mode
        || old.organization_access != input.organization_access
        || old.organization_auto_access != input.organization_auto_access;
    // Never let old restricted grants silently come back after the application
    // has been made open or personal-only and is later restricted again.
    let clear_grants =
        changed && (input.organization_access == "open" || input.tenant_mode == "personal");
    let limit = input.max_sessions;
    let tighten = limit > 0 && (old.max_sessions == 0 || limit < old.max_sessions);
    let mut active: apps::ActiveModel = old.into();
    input.apply(&mut active);
    active.update(&txn).await?;
    if tighten && !changed {
        super::app_session::prune(&txn, id, limit, idle_ttl).await?;
    }
    if clear_grants {
        txn.execute_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "DELETE FROM tenant_app_grants WHERE app_id=$1",
            [id.into()],
        ))
        .await?;
        txn.execute_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "UPDATE tenant_app_requests SET status='withdrawn',updated_at=now() WHERE app_id=$1 AND status='pending'",
            [id.into()],
        ))
        .await?;
    }
    if changed {
        super::session::SessionService::revoke_app_grants(&txn, id, None, "tenant_mode_changed")
            .await?;
    }
    txn.commit().await?;
    Ok(())
}

pub async fn toggle_status(
    db: &DatabaseConnection,
    actor: &Actor,
    id: uuid::Uuid,
) -> Result<(), ManagementError> {
    let txn = db.begin().await?;
    let access = permissions::authorize(&txn, actor).await?;
    permissions::app(&txn, &access, id, P::AppsManage).await?;

    let app = editable(&txn, id).await?;
    let status = match app.status {
        CommonStatus::Active => CommonStatus::Disabled,
        CommonStatus::Disabled => CommonStatus::Active,
    };
    let mut active: apps::ActiveModel = app.into();
    active.status = Set(status.clone());
    active.updated_at = Set(time::OffsetDateTime::now_utc());
    active.update(&txn).await?;
    if status == CommonStatus::Disabled {
        super::security::execute(&txn,"DELETE FROM notification_outbox WHERE enrollment_id IN (SELECT id FROM enrollments WHERE app_id=$1 AND status IN ('pending_verification','pending_approval','ready'))",vec![id.into()]).await?;
        super::security::execute(&txn,"UPDATE enrollments SET status='revoked' WHERE app_id=$1 AND status IN ('pending_verification','pending_approval','ready')",vec![id.into()]).await?;
        super::session::SessionService::revoke_app_grants(&txn, id, None, "app_disabled").await?;
    }
    txn.commit().await?;
    Ok(())
}
