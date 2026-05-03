use crate::api::response::{MessageResponse, PageData};
use crate::domain::abac;
use crate::domain::identity::error;
use crate::domain::identity::models::{
    BindRequest, CreateUserRequest, Identity, RegisterRequest, TokenResponse, UpdateMeRequest,
    UpdateUserRequest, User, UserDTO,
};
use crate::domain::identity::repo::{IdentityStore, SessionStore, UserAttributeStore, UserStore};
use crate::domain::oauth2::repo::{OAuth2TokenStore, TokenSigner};
use crate::shared::constants::identity::{DEFAULT_ROLE, PROVIDER_PASSWORD};
use crate::shared::error::AppError;
use crate::shared::patch::Patch;

pub async fn register_user(
    users: &dyn UserStore,
    sessions_store: &dyn SessionStore,
    signer: &dyn TokenSigner,
    req: &RegisterRequest,
    device: &str,
    location: &str,
    access_ttl_minutes: i64,
    refresh_ttl_days: i64,
) -> Result<TokenResponse, AppError> {
    let password_hash = hash_password(&req.password)?;
    let user = users.create_with_password(
        &req.username,
        req.email.as_deref(),
        req.phone.as_deref(),
        req.nickname.as_deref(),
        &password_hash,
    ).await?;

    issue_tokens(signer, sessions_store, &user, access_ttl_minutes, refresh_ttl_days, device, location).await
}

pub async fn create_user(users: &dyn UserStore, req: &CreateUserRequest) -> Result<UserDTO, AppError> {
    let password_hash = hash_password(&req.password)?;
    let user = users.create_with_password(
        &req.username,
        req.email.as_deref(),
        req.phone.as_deref(),
        req.nickname.as_deref(),
        &password_hash,
    ).await?;

    Ok(user.into())
}

pub async fn get_me(users: &dyn UserStore, user_id: uuid::Uuid) -> Result<UserDTO, AppError> {
    let user = users.find_by_id(user_id).await?.ok_or_else(error::user_not_found)?;
    Ok(user.into())
}

fn should_reset_email_verified(req: &UpdateMeRequest, current: &str) -> bool {
    match &req.email {
        Patch::Set(v) => v != current,
        Patch::Null => !current.is_empty(),
        Patch::Absent => false,
    }
}

fn should_reset_phone_verified(req: &UpdateMeRequest, current: &str) -> bool {
    match &req.phone {
        Patch::Set(v) => v != current,
        Patch::Null => !current.is_empty(),
        Patch::Absent => false,
    }
}

fn should_reset_admin_email_verified(req: &UpdateUserRequest, current: &str) -> bool {
    match &req.email {
        Patch::Set(v) => v != current,
        Patch::Null => !current.is_empty(),
        Patch::Absent => false,
    }
}

fn should_reset_admin_phone_verified(req: &UpdateUserRequest, current: &str) -> bool {
    match &req.phone {
        Patch::Set(v) => v != current,
        Patch::Null => !current.is_empty(),
        Patch::Absent => false,
    }
}

pub async fn update_me(
    users: &dyn UserStore,
    user_id: uuid::Uuid,
    req: &UpdateMeRequest,
) -> Result<UserDTO, AppError> {
    users.check_update_user_conflicts(
        user_id,
        None,
        req.email.as_set().map(|s| s.as_str()),
        req.phone.as_set().map(|s| s.as_str()),
    )
    .await?;
    let current = users.find_by_id(user_id)
        .await?
        .ok_or_else(error::user_not_found)?;
    let reset_email = should_reset_email_verified(req, &current.email.clone().unwrap_or_default());
    let reset_phone = should_reset_phone_verified(req, &current.phone.clone().unwrap_or_default());
    Ok(
        users.update_self(user_id, req, reset_email, reset_phone)
            .await?
            .into(),
    )
}

pub async fn list_users(
    users: &dyn UserStore,
    page: i64,
    page_size: i64,
) -> Result<PageData<UserDTO>, AppError> {
    let (users, total) = users.list(page, page_size).await?;
    let items = users.into_iter().map(UserDTO::from).collect();
    Ok(PageData::new(items, total, page, page_size))
}

pub async fn get_user(users: &dyn UserStore, id: uuid::Uuid) -> Result<UserDTO, AppError> {
    let user = users.find_by_id(id).await?.ok_or_else(error::user_not_found)?;
    Ok(user.into())
}

pub async fn update_user(
    users: &dyn UserStore,
    sessions_store: &dyn SessionStore,
    token_store: &dyn OAuth2TokenStore,
    id: uuid::Uuid,
    req: &UpdateUserRequest,
) -> Result<UserDTO, AppError> {
    users.check_update_user_conflicts(
        id,
        req.username.as_set().map(|s| s.as_str()),
        req.email.as_set().map(|s| s.as_str()),
        req.phone.as_set().map(|s| s.as_str()),
    )
    .await?;

    let current = users.find_by_id(id)
        .await?
        .ok_or_else(error::user_not_found)?;
    let reset_email =
        should_reset_admin_email_verified(req, &current.email.clone().unwrap_or_default());
    let reset_phone =
        should_reset_admin_phone_verified(req, &current.phone.clone().unwrap_or_default());

    let disabling = match req.status {
        Patch::Set(status) if status == 0 && current.is_active() => true,
        _ => false,
    };

    let user = users.update_admin(id, req, reset_email, reset_phone).await?;

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
    token_store: &dyn OAuth2TokenStore,
    id: uuid::Uuid,
) -> Result<MessageResponse, AppError> {
    users.delete(id).await?;
    if let Err(e) = sessions_store.revoke_all_for_user(id).await {
        tracing::warn!(error = %e, "failed to revoke sessions after user deletion");
    }
    if let Err(e) = token_store.revoke_all_for_user(id).await {
        tracing::warn!(error = %e, "failed to revoke oauth2 tokens after user deletion");
    }
    Ok(MessageResponse::success("user deleted"))
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
) -> Result<MessageResponse, AppError> {
    let existing = identities.find_by_user_and_provider(user_id, provider).await?;
    if existing.is_some() {
        return Err(error::provider_already_bound(provider));
    }

    Err(error::provider_binding_not_implemented(provider))
}

pub async fn unbind_identity(
    identities: &dyn IdentityStore,
    user_id: uuid::Uuid,
    provider: &str,
) -> Result<MessageResponse, AppError> {
    if provider == PROVIDER_PASSWORD {
        return Err(error::cannot_unbind_password());
    }

    let count = identities.count_by_user(user_id).await?;
    if count <= 1 {
        return Err(error::must_keep_one_login_method());
    }

    identities.delete(user_id, provider).await?;
    Ok(MessageResponse::success("provider unbound"))
}

pub async fn list_user_attributes(
    users: &dyn UserStore,
    attrs: &dyn UserAttributeStore,
    user_id: uuid::Uuid,
) -> Result<Vec<crate::domain::identity::dto::UserAttribute>, AppError> {
    users.find_by_id(user_id).await?.ok_or_else(error::user_not_found)?;
    attrs.list_by_user(user_id).await
}

pub async fn set_user_attributes(
    users: &dyn UserStore,
    attrs: &dyn UserAttributeStore,
    abac_cache: &dyn crate::domain::abac::repo::AbacCacheStore,
    cache_ttl: i64,
    user_id: uuid::Uuid,
    input: &crate::domain::identity::dto::SetAttributes,
) -> Result<MessageResponse, AppError> {
    users.find_by_id(user_id).await?.ok_or_else(error::user_not_found)?;
    attrs.upsert(user_id, &input.attributes).await?;
    abac::service::invalidate_user_cache_best_effort(abac_cache, user_id, cache_ttl).await;
    Ok(MessageResponse::success("attributes updated"))
}

pub async fn delete_user_attribute(
    users: &dyn UserStore,
    attrs: &dyn UserAttributeStore,
    abac_cache: &dyn crate::domain::abac::repo::AbacCacheStore,
    cache_ttl: i64,
    user_id: uuid::Uuid,
    key: &str,
) -> Result<MessageResponse, AppError> {
    users.find_by_id(user_id).await?.ok_or_else(error::user_not_found)?;
    attrs.delete_by_user(user_id, key).await?;
    abac::service::invalidate_user_cache_best_effort(abac_cache, user_id, cache_ttl).await;
    Ok(MessageResponse::success("attribute deleted"))
}

pub async fn issue_tokens(
    signer: &dyn TokenSigner,
    sessions_store: &dyn SessionStore,
    user: &User,
    access_ttl_minutes: i64,
    refresh_ttl_days: i64,
    device: &str,
    location: &str,
) -> Result<TokenResponse, AppError> {
    let user_id_str = user.id.to_string();
    let roles = vec![DEFAULT_ROLE.to_string()];

    let access_token = signer.sign_access_token(
        crate::domain::oauth2::repo::AccessTokenParams {
            sub: user_id_str,
            roles,
            scope: None,
            azp: None,
            app_id: None,
            sid: None,
            ttl_minutes: access_ttl_minutes,
        },
    )?;

    let (_identity_session, refresh_token) = sessions_store.create(
        user.id,
        refresh_ttl_days,
        device,
        location,
    ).await?;

    Ok(TokenResponse {
        access_token,
        refresh_token,
        user: user.clone().into(),
    })
}

pub fn hash_password(password: &str) -> Result<String, AppError> {
    crate::shared::crypto::hash_secret(password)
}
