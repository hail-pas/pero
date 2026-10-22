//! User administration shares the credential lock with login and recovery.
use super::{ManagementError, contact::ContactChannel, password::PasswordIdentityService};
use crate::db::{entity::users, enums::UserStatus};
use sea_orm::{ActiveModelTrait, DatabaseConnection, DbErr, Set, TransactionTrait};

async fn lock_user(
    db: &sea_orm::DatabaseTransaction,
    id: uuid::Uuid,
) -> Result<users::Model, ManagementError> {
    PasswordIdentityService::lock_user(db, id)
        .await
        .map_err(|error| match error {
            DbErr::RecordNotFound(_) => ManagementError::Invalid("not_found"),
            error => error.into(),
        })
}

pub struct UserUpdate {
    pub email: Option<String>,
    pub phone: Option<String>,
    pub nickname: Option<String>,
    pub avatar_url: Option<String>,
}

pub async fn update(
    db: &DatabaseConnection,
    id: uuid::Uuid,
    input: UserUpdate,
) -> Result<(), ManagementError> {
    pero_utils::redirect::validate_optional_public_http_url(input.avatar_url.as_deref())
        .map_err(|_| ManagementError::Invalid("invalid_url"))?;
    let txn = db.begin().await?;
    let user = lock_user(&txn, id).await?;
    let changed = user.email != input.email || user.phone != input.phone;
    let mut active: users::ActiveModel = user.clone().into();
    ContactChannel::Email.apply_user_contact_update(&user, &mut active, input.email);
    ContactChannel::Phone.apply_user_contact_update(&user, &mut active, input.phone);
    active.nickname = Set(input.nickname);
    active.avatar_url = Set(input.avatar_url);
    active.updated_at = Set(time::OffsetDateTime::now_utc());
    active.update(&txn).await?;
    if changed {
        super::contact::invalidate_contact_credentials(&txn, id, None).await?;
    }
    txn.commit().await?;
    Ok(())
}

pub async fn set_status(
    db: &DatabaseConnection,
    id: uuid::Uuid,
    actor: uuid::Uuid,
    status: UserStatus,
) -> Result<(), ManagementError> {
    if id == actor {
        return Err(ManagementError::Invalid("cannot_modify_self"));
    }
    let txn = db.begin().await?;
    let mut active: users::ActiveModel = lock_user(&txn, id).await?.into();
    active.status = Set(status.clone());
    active.updated_at = Set(time::OffsetDateTime::now_utc());
    active.update(&txn).await?;
    if status != UserStatus::Active {
        PasswordIdentityService::invalidate_reset_tokens(&txn, id).await?;
        super::session::SessionService::revoke_all_login_state_for_user_in_db(
            &txn,
            id,
            "user_status_changed",
        )
        .await?;
    }
    txn.commit().await?;
    Ok(())
}
