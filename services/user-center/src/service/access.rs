use super::permissions::{self, Actor, Permission as P};
use sea_orm::{
    ColumnTrait, ConnectionTrait, DatabaseConnection, DatabaseTransaction, DbBackend, EntityTrait,
    QueryFilter, QuerySelect, Set, Statement, TransactionTrait,
};
use uuid::Uuid;

use super::ManagementError;
use crate::db::entity::{apps as apps_entity, user_app_access as uaa, users};
use crate::db::enums::CommonStatus;

async fn lock_app_for_access_change(
    txn: &DatabaseTransaction,
    user_id: Uuid,
    app_id: Uuid,
) -> Result<users::Model, ManagementError> {
    // Match token issuance's app -> access lock order.
    apps_entity::Entity::find_by_id(app_id)
        .lock_shared()
        .one(txn)
        .await?
        .ok_or(ManagementError::Invalid("invalid_app_id"))?;
    let user = users::Entity::find_by_id(user_id)
        .filter(users::Column::DeletedAt.is_null())
        .one(txn)
        .await?
        .ok_or(ManagementError::Invalid("not_found"))?;
    Ok(user)
}

pub async fn grant_app(
    db: &DatabaseConnection,
    actor: &Actor,
    user_id: Uuid,
    app_id: Uuid,
) -> Result<(), ManagementError> {
    let txn = db.begin().await?;
    let access = permissions::authorize(&txn, actor).await?;
    permissions::app(&txn, &access, app_id, P::AppsMembersManage).await?;
    permissions::protect_user(&txn, &access, user_id).await?;

    let user = lock_app_for_access_change(&txn, user_id, app_id).await?;
    if user.status != crate::db::enums::UserStatus::Active {
        return Err(ManagementError::Invalid("not_found"));
    }
    write_app_access(&txn, user_id, app_id, CommonStatus::Active).await?;
    txn.commit().await?;
    Ok(())
}

pub(super) async fn write_app_access<C: ConnectionTrait>(
    db: &C,
    user_id: Uuid,
    app_id: Uuid,
    status: CommonStatus,
) -> Result<(), sea_orm::DbErr> {
    let now = time::OffsetDateTime::now_utc();
    uaa::Entity::insert(uaa::ActiveModel {
        user_id: Set(user_id),
        app_id: Set(app_id),
        status: Set(status),
        admission_origin: Set("explicit".to_owned()),
        created_at: Set(now),
        updated_at: Set(now),
        ..Default::default()
    })
    .on_conflict(
        sea_orm::sea_query::OnConflict::columns([uaa::Column::UserId, uaa::Column::AppId])
            .update_columns([
                uaa::Column::Status,
                uaa::Column::AdmissionOrigin,
                uaa::Column::UpdatedAt,
            ])
            .to_owned(),
    )
    .exec(db)
    .await?;
    Ok(())
}

async fn current_admission<C: ConnectionTrait>(
    db: &C,
    access: &uaa::Model,
) -> Result<bool, sea_orm::DbErr> {
    if access.status != CommonStatus::Active {
        return Ok(false);
    }
    if access.admission_origin == "explicit" {
        return Ok(true);
    }
    super::tenant_context::auto_eligible(db, access.user_id, access.app_id).await
}

/// OAuth may provision a super administrator's own entitlement before MFA/consent.
/// Ordinary users require explicit admission or current organization eligibility.
pub async fn ensure_oauth_app_access(
    db: &DatabaseConnection,
    session: &crate::state::session::SsoSession,
    app_id: Uuid,
    idle_ttl_seconds: u64,
) -> Result<bool, sea_orm::DbErr> {
    if let Some(access) = active_app_access(db, session.user_id, app_id).await?
        && current_admission(db, &access).await?
    {
        return Ok(true);
    }
    let super_admin =
        super::security::role(db, session.user_id).await?.as_deref() == Some("super_admin");
    let txn = db.begin().await?;
    let app = apps_entity::Entity::find_by_id(app_id)
        .lock_shared()
        .one(&txn)
        .await?;
    if !app.is_some_and(|a| a.status == CommonStatus::Active) {
        return Ok(false);
    }
    // Recheck admission under the app/access locks: a concurrent grant may have
    // completed since the initial read.
    let existing = uaa::Entity::find_by_id((session.user_id, app_id))
        .lock_exclusive()
        .one(&txn)
        .await?;
    if let Some(access) = existing.as_ref()
        && current_admission(&txn, access).await?
    {
        return Ok(true);
    }
    // An explicit disabled admission is a deny: organization auto-admission must not restore it.
    if !super_admin
        && (existing.is_some()
            || !super::tenant_context::auto_eligible(&txn, session.user_id, app_id).await?)
    {
        return Ok(false);
    }
    let user = users::Entity::find_by_id(session.user_id)
        .lock_shared()
        .one(&txn)
        .await?;
    if !user
        .is_some_and(|u| u.deleted_at.is_none() && u.status == crate::db::enums::UserStatus::Active)
    {
        return Ok(false);
    }
    // Role and app membership are checked again inside the write transaction.
    if super_admin
        && super::security::role(&txn, session.user_id)
            .await?
            .as_deref()
            != Some("super_admin")
    {
        return Ok(false);
    }
    let live_session = crate::db::helper::session::primary_query(
        time::OffsetDateTime::now_utc(),
        idle_ttl_seconds,
    )
    .filter(crate::db::entity::sso_sessions::Column::Id.eq(session.id))
    .filter(crate::db::entity::sso_sessions::Column::UserId.eq(session.user_id))
    .lock_shared()
    .one(&txn)
    .await?;
    if live_session.is_none() {
        return Ok(false);
    }
    if super_admin {
        write_app_access(&txn, session.user_id, app_id, CommonStatus::Active).await?;
    } else {
        // Never overwrite an explicit revocation or a grant racing with this insert.
        txn.execute_raw(Statement::from_sql_and_values(DbBackend::Postgres,
            "INSERT INTO user_app_access(user_id,app_id,admission_origin) VALUES($1,$2,'organization') ON CONFLICT DO NOTHING",
            [session.user_id.into(),app_id.into()])).await?;
    }
    txn.commit().await?;
    match active_app_access(db, session.user_id, app_id).await? {
        Some(access) => current_admission(db, &access).await,
        None => Ok(false),
    }
}

pub async fn revoke_app(
    db: &DatabaseConnection,
    actor: &Actor,
    user_id: Uuid,
    app_id: Uuid,
) -> Result<(), ManagementError> {
    let txn = db.begin().await?;
    let access = permissions::authorize(&txn, actor).await?;
    permissions::app(&txn, &access, app_id, P::AppsMembersManage).await?;
    permissions::protect_user(&txn, &access, user_id).await?;

    lock_app_for_access_change(&txn, user_id, app_id).await?;
    // Persist explicit denial even before the first organization auto-admission.
    write_app_access(&txn, user_id, app_id, CommonStatus::Disabled).await?;
    super::session::SessionService::revoke_app_grants(
        &txn,
        app_id,
        Some(user_id),
        "app_access_revoked",
    )
    .await?;
    txn.commit().await?;
    Ok(())
}

pub async fn active_app_access<C: ConnectionTrait>(
    db: &C,
    user_id: Uuid,
    app_id: Uuid,
) -> Result<Option<uaa::Model>, sea_orm::DbErr> {
    uaa::Entity::find_by_id((user_id, app_id))
        .filter(uaa::Column::Status.eq(CommonStatus::Active))
        .inner_join(apps_entity::Entity)
        .filter(apps_entity::Column::Status.eq(CommonStatus::Active))
        .one(db)
        .await
}

pub struct GrantAccess {
    pub(crate) user: users::Model,
    pub(crate) app: apps_entity::Model,
    pub(crate) token_version: i64,
}

/// Lock policy rows before a grant row so revocation cannot miss a concurrent issuance.
pub async fn lock_grant_access<C: ConnectionTrait>(
    db: &C,
    user_id: Uuid,
    app_id: Uuid,
) -> Result<Option<GrantAccess>, sea_orm::DbErr> {
    use crate::db::enums::UserStatus;
    let app = apps_entity::Entity::find_by_id(app_id)
        .lock_shared()
        .one(db)
        .await?;
    let Some(app) = app.filter(|app| app.status == CommonStatus::Active) else {
        return Ok(None);
    };
    let access = uaa::Entity::find_by_id((user_id, app_id))
        .lock_exclusive()
        .one(db)
        .await?;
    let Some(access) = access.filter(|access| access.status == CommonStatus::Active) else {
        return Ok(None);
    };
    let user = users::Entity::find_by_id(user_id)
        .lock_shared()
        .one(db)
        .await?;
    Ok(user
        .filter(|user| user.deleted_at.is_none() && user.status == UserStatus::Active)
        .map(|user| GrantAccess {
            user,
            app,
            token_version: access.token_version,
        }))
}
