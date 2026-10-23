//! User administration shares the credential lock with login and recovery.
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

pub struct UserCreate {
    pub username: String,
    pub password: String,
    pub profile: UserUpdate,
}

pub async fn create(
    db: &DatabaseConnection,
    policy: &crate::config::PasswordConfig,
    input: UserCreate,
) -> Result<(), ManagementError> {
    let username = input.username.trim();
    if username.is_empty() || input.password.is_empty() {
        return Err(ManagementError::Invalid("username_and_password_required"));
    }
    crate::db::helper::user::validate_username(username)
        .map_err(|_| ManagementError::Invalid("username_chars_invalid"))?;
    policy
        .validate_password(&input.password)
        .map_err(ManagementError::Validation)?;
    pero_utils::redirect::validate_optional_public_http_url(input.profile.avatar_url.as_deref())
        .map_err(|_| ManagementError::Invalid("invalid_url"))?;
    if users::Entity::find()
        .filter(users::Column::Username.eq(username))
        .one(db)
        .await?
        .is_some()
    {
        return Err(ManagementError::Invalid("username_exists"));
    }
    let hash = PasswordIdentityService::hash_password(&input.password).await?;
    let txn = db.begin().await?;
    let provider = crate::db::helper::identity_provider::find_local_provider(&txn).await?;
    let now = time::OffsetDateTime::now_utc();
    let user = users::ActiveModel {
        id: Set(uuid::Uuid::now_v7()),
        username: Set(username.to_owned()),
        email: Set(input.profile.email),
        phone: Set(input.profile.phone),
        nickname: Set(input.profile.nickname),
        avatar_url: Set(input.profile.avatar_url),
        status: Set(UserStatus::Active),
        created_at: Set(now),
        updated_at: Set(now),
        deleted_at: Set(None),
        email_verified_at: Set(None),
        phone_verified_at: Set(None),
    }
    .insert(&txn)
    .await?;
    PasswordIdentityService::create_hashed(
        &txn,
        user.id,
        provider.id,
        user.id.to_string(),
        hash,
        now,
    )
    .await?;
    txn.commit().await?;
    Ok(())
}

pub async fn reset_password(
    db: &DatabaseConnection,
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
    txn.commit().await?;
    Ok(())
}
