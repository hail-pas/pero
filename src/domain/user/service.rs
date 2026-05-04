use crate::domain::abac;
use crate::domain::auth::repo::SessionStore;
use crate::domain::credential::repo::IdentityStore;
use crate::domain::oauth::repo::RefreshTokenStore;
use crate::domain::user::error;
use crate::domain::user::models::{
    BindRequest, Identity, UpdateMeRequest, UpdateUserRequest, UserDTO,
};
use crate::domain::user::repo::{UserAttributeStore, UserStore};
use crate::shared::constants::identity::PROVIDER_PASSWORD;
use crate::shared::error::AppError;
use crate::shared::patch::FieldUpdate;

pub async fn get_me(users: &dyn UserStore, user_id: uuid::Uuid) -> Result<UserDTO, AppError> {
    let user = users
        .find_by_id(user_id)
        .await?
        .ok_or_else(error::user_not_found)?;
    Ok(user.into())
}

fn should_reset_email_verified(req: &UpdateMeRequest, current: &str) -> bool {
    match &req.email {
        FieldUpdate::Set(v) => v != current,
        FieldUpdate::Clear => !current.is_empty(),
        FieldUpdate::Unchanged => false,
    }
}

fn should_reset_phone_verified(req: &UpdateMeRequest, current: &str) -> bool {
    match &req.phone {
        FieldUpdate::Set(v) => v != current,
        FieldUpdate::Clear => !current.is_empty(),
        FieldUpdate::Unchanged => false,
    }
}

fn should_reset_admin_email_verified(req: &UpdateUserRequest, current: &str) -> bool {
    match &req.email {
        FieldUpdate::Set(v) => v != current,
        FieldUpdate::Clear => !current.is_empty(),
        FieldUpdate::Unchanged => false,
    }
}

fn should_reset_admin_phone_verified(req: &UpdateUserRequest, current: &str) -> bool {
    match &req.phone {
        FieldUpdate::Set(v) => v != current,
        FieldUpdate::Clear => !current.is_empty(),
        FieldUpdate::Unchanged => false,
    }
}

pub async fn update_me(
    users: &dyn UserStore,
    user_id: uuid::Uuid,
    req: &UpdateMeRequest,
) -> Result<UserDTO, AppError> {
    users
        .check_update_user_conflicts(
            user_id,
            None,
            req.email.as_set().map(|s| s.as_str()),
            req.phone.as_set().map(|s| s.as_str()),
        )
        .await?;
    let current = users
        .find_by_id(user_id)
        .await?
        .ok_or_else(error::user_not_found)?;
    let reset_email = should_reset_email_verified(req, &current.email.clone().unwrap_or_default());
    let reset_phone = should_reset_phone_verified(req, &current.phone.clone().unwrap_or_default());
    Ok(users
        .update_self(user_id, req, reset_email, reset_phone)
        .await?
        .into())
}

pub async fn list_users(
    users: &dyn UserStore,
    page: i64,
    page_size: i64,
) -> Result<(Vec<UserDTO>, i64), AppError> {
    let (users, total) = users.list(page, page_size).await?;
    let items = users.into_iter().map(UserDTO::from).collect();
    Ok((items, total))
}

pub async fn get_user(users: &dyn UserStore, id: uuid::Uuid) -> Result<UserDTO, AppError> {
    let user = users
        .find_by_id(id)
        .await?
        .ok_or_else(error::user_not_found)?;
    Ok(user.into())
}

pub async fn update_user(
    users: &dyn UserStore,
    sessions_store: &dyn SessionStore,
    token_store: &dyn RefreshTokenStore,
    id: uuid::Uuid,
    req: &UpdateUserRequest,
) -> Result<UserDTO, AppError> {
    users
        .check_update_user_conflicts(
            id,
            req.username.as_set().map(|s| s.as_str()),
            req.email.as_set().map(|s| s.as_str()),
            req.phone.as_set().map(|s| s.as_str()),
        )
        .await?;

    let current = users
        .find_by_id(id)
        .await?
        .ok_or_else(error::user_not_found)?;
    let reset_email =
        should_reset_admin_email_verified(req, &current.email.clone().unwrap_or_default());
    let reset_phone =
        should_reset_admin_phone_verified(req, &current.phone.clone().unwrap_or_default());

    let disabling = match req.status {
        FieldUpdate::Set(status) if status == 0 && current.is_active() => true,
        _ => false,
    };

    let user = users
        .update_admin(id, req, reset_email, reset_phone)
        .await?;

    if disabling {
        if let Err(e) = sessions_store.revoke_all_for_user(id).await {
            tracing::warn!(error = %e, "failed to revoke sessions after user disable");
        }
        if let Err(e) = token_store.revoke_all_for_user(id).await {
            tracing::warn!(error = %e, "failed to revoke oauth2 tokens after user disable");
        }
    }

    Ok(user.into())
}

pub async fn delete_user(
    users: &dyn UserStore,
    sessions_store: &dyn SessionStore,
    token_store: &dyn RefreshTokenStore,
    id: uuid::Uuid,
) -> Result<(), AppError> {
    users.delete(id).await?;
    if let Err(e) = sessions_store.revoke_all_for_user(id).await {
        tracing::warn!(error = %e, "failed to revoke sessions after user deletion");
    }
    if let Err(e) = token_store.revoke_all_for_user(id).await {
        tracing::warn!(error = %e, "failed to revoke oauth2 tokens after user deletion");
    }
    Ok(())
}

pub async fn list_identities(
    identities: &dyn IdentityStore,
    user_id: uuid::Uuid,
) -> Result<Vec<Identity>, AppError> {
    identities.list_by_user(user_id).await
}

pub async fn bind_identity(
    identities: &dyn IdentityStore,
    user_id: uuid::Uuid,
    provider: &str,
    _req: &BindRequest,
) -> Result<(), AppError> {
    let existing = identities
        .find_by_user_and_provider(user_id, provider)
        .await?;
    if existing.is_some() {
        return Err(error::provider_already_bound(provider));
    }

    Err(error::provider_binding_not_implemented(provider))
}

pub async fn unbind_identity(
    identities: &dyn IdentityStore,
    user_id: uuid::Uuid,
    provider: &str,
) -> Result<(), AppError> {
    if provider == PROVIDER_PASSWORD {
        return Err(error::cannot_unbind_password());
    }

    let count = identities.count_by_user(user_id).await?;
    if count <= 1 {
        return Err(error::must_keep_one_login_method());
    }

    identities.delete(user_id, provider).await
}

pub async fn list_user_attributes(
    users: &dyn UserStore,
    attrs: &dyn UserAttributeStore,
    user_id: uuid::Uuid,
) -> Result<Vec<crate::domain::user::dto::UserAttribute>, AppError> {
    users
        .find_by_id(user_id)
        .await?
        .ok_or_else(error::user_not_found)?;
    attrs.list_by_user(user_id).await
}

pub async fn set_user_attributes(
    users: &dyn UserStore,
    attrs: &dyn UserAttributeStore,
    abac_cache: &dyn crate::domain::abac::repo::AbacCacheStore,
    cache_ttl: i64,
    user_id: uuid::Uuid,
    input: &crate::domain::user::dto::SetAttributes,
) -> Result<(), AppError> {
    users
        .find_by_id(user_id)
        .await?
        .ok_or_else(error::user_not_found)?;
    attrs.upsert(user_id, &input.attributes).await?;
    abac::service::invalidate_user_cache_best_effort(abac_cache, user_id, cache_ttl).await;
    Ok(())
}

pub async fn delete_user_attribute(
    users: &dyn UserStore,
    attrs: &dyn UserAttributeStore,
    abac_cache: &dyn crate::domain::abac::repo::AbacCacheStore,
    cache_ttl: i64,
    user_id: uuid::Uuid,
    key: &str,
) -> Result<(), AppError> {
    users
        .find_by_id(user_id)
        .await?
        .ok_or_else(error::user_not_found)?;
    attrs.delete_by_user(user_id, key).await?;
    abac::service::invalidate_user_cache_best_effort(abac_cache, user_id, cache_ttl).await;
    Ok(())
}
