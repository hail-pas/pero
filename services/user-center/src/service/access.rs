use super::permissions::{self, Actor, Permission as P};
use sea_orm::{
    ColumnTrait, ConnectionTrait, DatabaseConnection, DatabaseTransaction, EntityTrait,
    QueryFilter, QuerySelect, Set, TransactionTrait, sea_query::Expr,
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
    write_app_access(&txn, user_id, app_id).await?;
    txn.commit().await?;
    Ok(())
}

async fn write_app_access<C: ConnectionTrait>(
    db: &C,
    user_id: Uuid,
    app_id: Uuid,
) -> Result<(), sea_orm::DbErr> {
    let now = time::OffsetDateTime::now_utc();
    uaa::Entity::insert(uaa::ActiveModel {
        user_id: Set(user_id),
        app_id: Set(app_id),
        status: Set(CommonStatus::Active),
        created_at: Set(now),
        updated_at: Set(now),
        ..Default::default()
    })
    .on_conflict(
        sea_orm::sea_query::OnConflict::columns([uaa::Column::UserId, uaa::Column::AppId])
            .update_columns([uaa::Column::Status, uaa::Column::UpdatedAt])
            .to_owned(),
    )
    .exec(db)
    .await?;
    Ok(())
}

/// OAuth may provision a super administrator's own entitlement before MFA/consent.
/// Ordinary administrators and users still require explicit application admission.
pub async fn ensure_oauth_app_access(
    db: &DatabaseConnection,
    session: &crate::state::session::SsoSession,
    app_id: Uuid,
    idle_ttl_seconds: u64,
) -> Result<bool, sea_orm::DbErr> {
    if active_app_access(db, session.user_id, app_id)
        .await?
        .is_some()
    {
        return Ok(true);
    }
    if super::security::role(db, session.user_id).await?.as_deref() != Some("super_admin") {
        return Ok(false);
    }
    let txn = db.begin().await?;
    let app = apps_entity::Entity::find_by_id(app_id)
        .lock_shared()
        .one(&txn)
        .await?;
    if !app.is_some_and(|a| a.status == CommonStatus::Active) {
        return Ok(false);
    }
    // Keep the app -> access -> user lock order used by token issuance.
    uaa::Entity::find_by_id((session.user_id, app_id))
        .lock_exclusive()
        .one(&txn)
        .await?;
    let user = users::Entity::find_by_id(session.user_id)
        .lock_shared()
        .one(&txn)
        .await?;
    if !user
        .is_some_and(|u| u.deleted_at.is_none() && u.status == crate::db::enums::UserStatus::Active)
    {
        return Ok(false);
    }
    // Role changes take the user's exclusive policy lock. Recheck under that lock.
    if super::security::role(&txn, session.user_id)
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
    write_app_access(&txn, session.user_id, app_id).await?;
    txn.commit().await?;
    tracing::info!(user_id = %session.user_id, %app_id, "Automatically granted super administrator application access");
    Ok(true)
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
    uaa::Entity::update_many()
        .col_expr(uaa::Column::Status, Expr::value(CommonStatus::Disabled))
        .col_expr(
            uaa::Column::UpdatedAt,
            Expr::value(time::OffsetDateTime::now_utc()),
        )
        .filter(uaa::Column::UserId.eq(user_id))
        .filter(uaa::Column::AppId.eq(app_id))
        .exec(&txn)
        .await?;
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

/// Lock policy rows before a grant row so revocation cannot miss a concurrent issuance.
pub async fn lock_grant_access<C: ConnectionTrait>(
    db: &C,
    user_id: Uuid,
    app_id: Uuid,
) -> Result<Option<uaa::Model>, sea_orm::DbErr> {
    use crate::db::enums::UserStatus;
    let app = apps_entity::Entity::find_by_id(app_id)
        .lock_shared()
        .one(db)
        .await?;
    if !app.is_some_and(|app| app.status == CommonStatus::Active) {
        return Ok(None);
    }
    let access = uaa::Entity::find_by_id((user_id, app_id))
        .lock_shared()
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
        .map(|_| access))
}
