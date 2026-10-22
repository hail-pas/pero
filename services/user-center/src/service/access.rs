use sea_orm::{ActiveModelTrait, ConnectionTrait, DatabaseTransaction, EntityTrait, Set};
use uuid::Uuid;

use crate::db::entity::{
    apps as apps_entity, authorization_requests as ar, user_app_access as uaa,
};
use crate::db::enums::CommonStatus;

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
    };
    if let Err(e) = access.insert(txn).await
        && !crate::db::error::is_unique_violation(&e)
    {
        return Err(e);
    }
    Ok(())
}

pub async fn can_user_access_active_app<C>(
    db: &C,
    user_id: Uuid,
    app_id: Uuid,
) -> Result<bool, sea_orm::DbErr>
where
    C: ConnectionTrait,
{
    let app = apps_entity::Entity::find_by_id(app_id).one(db).await?;
    if !app.is_some_and(|app| app.status == CommonStatus::Active) {
        return Ok(false);
    }

    let access = uaa::Entity::find_by_id((user_id, app_id)).one(db).await?;
    Ok(access.is_some_and(|access| access.status == CommonStatus::Active))
}

/// Lock policy rows before a grant row so revocation cannot miss a concurrent issuance.
pub async fn lock_grant_access<C: ConnectionTrait>(
    db: &C,
    user_id: Uuid,
    app_id: Uuid,
) -> Result<bool, sea_orm::DbErr> {
    use crate::db::{entity::users, enums::UserStatus};
    use sea_orm::QuerySelect;
    let app = apps_entity::Entity::find_by_id(app_id)
        .lock_shared()
        .one(db)
        .await?;
    if !app.is_some_and(|app| app.status == CommonStatus::Active) {
        return Ok(false);
    }
    let access = uaa::Entity::find_by_id((user_id, app_id))
        .lock_shared()
        .one(db)
        .await?;
    if !access.is_some_and(|access| access.status == CommonStatus::Active) {
        return Ok(false);
    }
    let user = users::Entity::find_by_id(user_id)
        .lock_shared()
        .one(db)
        .await?;
    Ok(user.is_some_and(|user| user.deleted_at.is_none() && user.status == UserStatus::Active))
}
