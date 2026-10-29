use super::permissions::{self, Actor, Permission as P};
// User administration shares the credential lock with login and recovery.
use super::{ManagementError, contact::ContactChannel, password::PasswordIdentityService};
use crate::db::{
    entity::{identities, users},
    enums::{IdentityKind, UserStatus},
};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, DbErr, EntityTrait, QueryFilter, Set,
    TransactionTrait,
};

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
    pub email: Option<Option<String>>,
    pub phone: Option<Option<String>>,
    pub nickname: Option<Option<String>>,
    pub avatar_url: Option<Option<String>>,
}

pub async fn update(
    db: &DatabaseConnection,
    actor: &Actor,
    id: uuid::Uuid,
    input: UserUpdate,
) -> Result<(), ManagementError> {
    pero_utils::redirect::validate_optional_public_http_url(
        input.avatar_url.as_ref().and_then(|v| v.as_deref()),
    )
    .map_err(|_| ManagementError::Invalid("invalid_url"))?;
    let txn = db.begin().await?;
    let access = permissions::authorize(&txn, actor).await?;
    permissions::protect_user(&txn, &access, id).await?;

    let user = lock_user(&txn, id).await?;
    if input.nickname.is_some() || input.avatar_url.is_some() {
        access.require_global(P::UsersUpdate)?;
    }
    if input.email.is_some() || input.phone.is_some() {
        access.require_global(P::UsersContactUpdate)?;
    }
    for (channel, value, error) in [
        (ContactChannel::Email, &input.email, "email_invalid"),
        (ContactChannel::Phone, &input.phone, "phone_invalid"),
    ] {
        if value
            .as_ref()
            .and_then(|value| value.as_deref())
            .is_some_and(|value| !channel.is_valid_format(value))
        {
            return Err(ManagementError::Invalid(error));
        }
    }
    let changed = input.email.as_ref().is_some_and(|v| v != &user.email)
        || input.phone.as_ref().is_some_and(|v| v != &user.phone);
    let mut active: users::ActiveModel = user.clone().into();
    if let Some(email) = input.email {
        ContactChannel::Email.apply_user_contact_update(&user, &mut active, email);
    }

    if let Some(phone) = input.phone {
        ContactChannel::Phone.apply_user_contact_update(&user, &mut active, phone);
    }

    if let Some(nickname) = input.nickname {
        active.nickname = Set(nickname);
    }
    if let Some(avatar) = input.avatar_url {
        active.avatar_url = Set(avatar);
    }
    active.updated_at = Set(time::OffsetDateTime::now_utc());
    active.update(&txn).await?;
    if changed {
        super::contact::invalidate_contact_credentials(&txn, id, None).await?;
        super::security::notify(&txn, &user, "contact_changed").await?;
    }
    txn.commit().await?;
    Ok(())
}

pub async fn set_status(
    db: &DatabaseConnection,
    actor: &Actor,
    id: uuid::Uuid,
    status: UserStatus,
) -> Result<(), ManagementError> {
    let txn = db.begin().await?;
    let access = permissions::authorize(&txn, actor).await?;
    permissions::protect_user(&txn, &access, id).await?;
    if id == actor.session.user_id {
        return Err(ManagementError::Invalid("cannot_modify_self"));
    }
    access.require_global(P::UsersStatusUpdate)?;

    if status != UserStatus::Active {
        super::admin::protect_last_super_admin(&txn, id).await?;
        super::enrollment::invalidate_sponsor(&txn, id).await?;
    }
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

pub async fn reset_password(
    db: &DatabaseConnection,
    actor: &Actor,
    policy: &crate::config::PasswordConfig,
    id: uuid::Uuid,
    password: &str,
) -> Result<(), ManagementError> {
    if password.is_empty() {
        return Err(ManagementError::Invalid("password_required"));
    }
    policy
        .validate_password(password)
        .map_err(ManagementError::Validation)?;
    let hash = PasswordIdentityService::hash_password(password).await?;
    let txn = db.begin().await?;
    let access = permissions::authorize(&txn, actor).await?;
    permissions::protect_user(&txn, &access, id).await?;
    access.require_global(P::UsersPasswordReset)?;

    let user = lock_user(&txn, id).await?;
    let identity = identities::Entity::find()
        .filter(identities::Column::UserId.eq(user.id))
        .filter(identities::Column::Kind.eq(IdentityKind::Password))
        .filter(identities::Column::UnboundAt.is_null())
        .one(&txn)
        .await?
        .ok_or(ManagementError::Invalid("no_password_identity"))?;
    PasswordIdentityService::update_hashed(&txn, identity, hash, time::OffsetDateTime::now_utc())
        .await?;
    super::session::SessionService::revoke_all_login_state_for_user_in_db(
        &txn,
        id,
        "admin_password_reset",
    )
    .await?;
    super::security::notify(&txn, &user, "admin_password_reset").await?;
    txn.commit().await?;
    Ok(())
}
