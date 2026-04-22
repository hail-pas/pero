use crate::domains::abac;
use crate::domains::identity::helpers;
use crate::domains::identity::models::{
    BindRequest, CreateUserRequest, Identity, RegisterRequest, TokenResponse, UpdateMeRequest,
    UpdateUserRequest, UserDTO,
};
use crate::domains::identity::repos::user_attr::{SetAttributes, UserAttribute, UserAttributeRepo};
use crate::domains::identity::repos::{IdentityRepo, UserRepo};
use crate::domains::identity::session;
use crate::shared::constants::identity::PROVIDER_PASSWORD;
use crate::shared::error::AppError;
use crate::shared::response::{MessageResponse, PageData};
use crate::shared::state::AppState;

pub async fn register_user(
    state: &AppState,
    req: &RegisterRequest,
) -> Result<TokenResponse, AppError> {
    let mut tx = state.db.begin().await?;
    let user = helpers::create_user_with_password(
        &mut tx,
        &req.username,
        &req.email,
        req.phone.as_deref(),
        req.nickname.as_deref(),
        &req.password,
    )
    .await?;
    tx.commit().await?;

    helpers::issue_tokens(state, &user).await
}

pub async fn create_user(state: &AppState, req: &CreateUserRequest) -> Result<UserDTO, AppError> {
    let mut tx = state.db.begin().await?;
    let user = helpers::create_user_with_password(
        &mut tx,
        &req.username,
        &req.email,
        req.phone.as_deref(),
        req.nickname.as_deref(),
        &req.password,
    )
    .await?;
    tx.commit().await?;

    Ok(user.into())
}

pub async fn get_me(state: &AppState, user_id: uuid::Uuid) -> Result<UserDTO, AppError> {
    Ok(UserRepo::find_by_id_or_err(&state.db, user_id)
        .await?
        .into())
}

pub async fn update_me(
    state: &AppState,
    user_id: uuid::Uuid,
    req: &UpdateMeRequest,
) -> Result<UserDTO, AppError> {
    Ok(UserRepo::update_me(&state.db, user_id, req).await?.into())
}

pub async fn list_users(
    state: &AppState,
    page: i64,
    page_size: i64,
) -> Result<PageData<UserDTO>, AppError> {
    let (users, total) = UserRepo::list(&state.db, page, page_size).await?;
    let items = users.into_iter().map(UserDTO::from).collect();
    Ok(PageData::new(items, total, page, page_size))
}

pub async fn get_user(state: &AppState, id: uuid::Uuid) -> Result<UserDTO, AppError> {
    Ok(UserRepo::find_by_id_or_err(&state.db, id).await?.into())
}

pub async fn update_user(
    state: &AppState,
    id: uuid::Uuid,
    req: &UpdateUserRequest,
) -> Result<UserDTO, AppError> {
    let mut tx = state.db.begin().await?;

    helpers::validate_update_user(&mut *tx, id, req.username.as_deref(), req.email.as_deref())
        .await?;

    let user = UserRepo::update(&mut *tx, id, req).await?;
    tx.commit().await?;

    Ok(user.into())
}

pub async fn delete_user(state: &AppState, id: uuid::Uuid) -> Result<MessageResponse, AppError> {
    session::revoke_user_sessions(&state.cache, id).await?;
    UserRepo::delete(&state.db, id).await?;
    Ok(MessageResponse::success("user deleted"))
}

pub async fn list_identities(
    state: &AppState,
    user_id: uuid::Uuid,
) -> Result<Vec<Identity>, AppError> {
    IdentityRepo::list_by_user(&state.db, user_id).await
}

pub async fn bind_identity(
    state: &AppState,
    user_id: uuid::Uuid,
    provider: &str,
    _req: &BindRequest,
) -> Result<MessageResponse, AppError> {
    let existing = IdentityRepo::find_by_user_and_provider(&state.db, user_id, provider).await?;
    if existing.is_some() {
        return Err(AppError::Conflict(format!(
            "provider '{}' already bound",
            provider
        )));
    }

    Err(AppError::BadRequest(format!(
        "provider '{}' binding not yet implemented",
        provider
    )))
}

pub async fn unbind_identity(
    state: &AppState,
    user_id: uuid::Uuid,
    provider: &str,
) -> Result<MessageResponse, AppError> {
    if provider == PROVIDER_PASSWORD {
        return Err(AppError::BadRequest(
            "cannot unbind password identity".into(),
        ));
    }

    let count = IdentityRepo::count_by_user(&state.db, user_id).await?;
    if count <= 1 {
        return Err(AppError::BadRequest(
            "must keep at least one login method".into(),
        ));
    }

    IdentityRepo::delete(&state.db, user_id, provider).await?;
    Ok(MessageResponse::success("provider unbound"))
}

pub async fn list_user_attributes(
    state: &AppState,
    user_id: uuid::Uuid,
) -> Result<Vec<UserAttribute>, AppError> {
    UserRepo::find_by_id_or_err(&state.db, user_id).await?;
    UserAttributeRepo::list_by_user(&state.db, user_id).await
}

pub async fn set_user_attributes(
    state: &AppState,
    user_id: uuid::Uuid,
    input: &SetAttributes,
) -> Result<MessageResponse, AppError> {
    UserRepo::find_by_id_or_err(&state.db, user_id).await?;
    UserAttributeRepo::upsert(&state.db, user_id, &input.attributes).await?;
    abac::service::invalidate_user_cache_best_effort(state, user_id).await;
    Ok(MessageResponse::success("attributes updated"))
}

pub async fn delete_user_attribute(
    state: &AppState,
    user_id: uuid::Uuid,
    key: &str,
) -> Result<MessageResponse, AppError> {
    UserRepo::find_by_id_or_err(&state.db, user_id).await?;
    UserAttributeRepo::delete_by_user(&state.db, user_id, key).await?;
    abac::service::invalidate_user_cache_best_effort(state, user_id).await;
    Ok(MessageResponse::success("attribute deleted"))
}
