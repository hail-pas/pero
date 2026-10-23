use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DatabaseConnection, DatabaseTransaction,
    EntityTrait, QueryFilter, QuerySelect, Set, TransactionTrait, sea_query::Expr,
};
use uuid::Uuid;

use super::ManagementError;
use crate::db::entity::{
    apps as apps_entity, authorization_requests as ar, user_app_access as uaa, users,
};
use crate::db::enums::CommonStatus;

async fn lock_app_for_access_change(
    txn: &DatabaseTransaction,
    user_id: Uuid,
    app_id: Uuid,
) -> Result<(), ManagementError> {
    // Match token issuance's app -> access lock order.
    apps_entity::Entity::find_by_id(app_id)
        .lock_shared()
        .one(txn)
        .await?
        .ok_or(ManagementError::Invalid("invalid_app_id"))?;
    users::Entity::find_by_id(user_id)
        .filter(users::Column::DeletedAt.is_null())
        .one(txn)
        .await?
        .ok_or(ManagementError::Invalid("not_found"))?;
    Ok(())
}

pub async fn grant_app(
    db: &DatabaseConnection,
    user_id: Uuid,
    app_id: Uuid,
) -> Result<(), ManagementError> {
    let txn = db.begin().await?;
    lock_app_for_access_change(&txn, user_id, app_id).await?;
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
    .exec(&txn)
    .await?;
    txn.commit().await?;
    Ok(())
}

pub async fn revoke_app(
    db: &DatabaseConnection,
    user_id: Uuid,
    app_id: Uuid,
) -> Result<(), ManagementError> {
    let txn = db.begin().await?;
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

pub async fn insert_auto_access(
    txn: &DatabaseTransaction,
    user_id: Uuid,
    auth_request_id: Option<Uuid>,
    now: time::OffsetDateTime,
) -> Result<(), sea_orm::DbErr> {
    let Some(auth_req_id) = auth_request_id else {
        return Ok(());
    };
    let Some(auth_req) = ar::Entity::find_by_id(auth_req_id).one(txn).await? else {
        return Ok(());
    };
    let Some(app) = apps_entity::Entity::find_by_id(auth_req.app_id)
        .one(txn)
        .await?
    else {
        return Ok(());
    };
    if !app.auto_access {
        return Ok(());
    }

    let access = uaa::ActiveModel {
        user_id: Set(user_id),
        app_id: Set(app.id),
        status: Set(CommonStatus::Active),
        created_at: Set(now),
        updated_at: Set(now),
        ..Default::default()
    };
    if let Err(e) = access.insert(txn).await
        && !crate::db::error::is_unique_violation(&e)
    {
        return Err(e);
    }
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
