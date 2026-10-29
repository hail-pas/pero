use super::permissions::{self, Actor, Permission as P};
// Application policy mutations hold the policy lock through grant revocation.
use super::ManagementError;
use crate::db::{
    entity::apps,
    enums::{AppType, CommonStatus},
};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QuerySelect, Set,
    TransactionTrait,
};

pub struct AppUpdate {
    pub name: String,
    pub app_type: AppType,
    pub description: Option<String>,
    pub homepage_url: Option<String>,
    pub logo_url: Option<String>,
}

impl AppUpdate {
    fn validate(&self) -> Result<(), ManagementError> {
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
        active.name = Set(self.name);
        active.r#type = Set(self.app_type);
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
) -> Result<(), ManagementError> {
    input.validate()?;
    let txn = db.begin().await?;
    let access = permissions::authorize(&txn, actor).await?;
    permissions::app(&txn, &access, id, P::AppsManage).await?;

    let mut active: apps::ActiveModel = editable(&txn, id).await?.into();
    input.apply(&mut active);
    active.update(&txn).await?;
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
