use crate::domain::abac;
use crate::domain::identity::error;
use crate::domain::identity::models::{
    BindRequest, CreateUserRequest, Identity, RegisterRequest, TokenResponse, UpdateMeRequest,
    UpdateUserRequest, User, UserDTO,
};
use crate::domain::identity::store::{IdentityRepo, SetAttributes, UserAttribute, UserAttributeRepo, UserRepo};
use crate::domain::identity::session;
use crate::domain::oauth2::store::RefreshTokenRepo;
use crate::shared::constants::identity::{DEFAULT_ROLE, PROVIDER_PASSWORD};
use crate::shared::error::AppError;
use crate::api::response::{MessageResponse, PageData};
use crate::infra::jwt;
use crate::shared::state::AppState;
use uuid::Uuid;

pub async fn register_user(
    state: &AppState,
    req: &RegisterRequest,
) -> Result<TokenResponse, AppError> {
    let mut tx = state.db.begin().await?;
    let user = create_user_with_password(
        &mut tx,
        &req.username,
        &req.email,
        req.phone.as_deref(),
        req.nickname.as_deref(),
        &req.password,
    )
    .await?;
    tx.commit().await?;

    issue_tokens(state, &user).await
}

pub async fn create_user(state: &AppState, req: &CreateUserRequest) -> Result<UserDTO, AppError> {
    let mut tx = state.db.begin().await?;
    let user = create_user_with_password(
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

    validate_update_user(&mut *tx, id, req.username.as_deref(), req.email.as_deref())
        .await?;

    let user = UserRepo::update(&mut *tx, id, req).await?;
    tx.commit().await?;

    Ok(user.into())
}

pub async fn delete_user(state: &AppState, id: uuid::Uuid) -> Result<MessageResponse, AppError> {
    UserRepo::delete(&state.db, id).await?;
    if let Err(e) = session::revoke_user_sessions(&state.cache, id).await {
        tracing::warn!(error = %e, "failed to revoke sessions after user deletion");
    }
    if let Err(e) = RefreshTokenRepo::revoke_all_for_user(&state.db, id).await {
        tracing::warn!(error = %e, "failed to revoke oauth2 tokens after user deletion");
    }
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
        return Err(error::provider_already_bound(provider));
    }

    Err(error::provider_binding_not_implemented(provider))
}

pub async fn unbind_identity(
    state: &AppState,
    user_id: uuid::Uuid,
    provider: &str,
) -> Result<MessageResponse, AppError> {
    if provider == PROVIDER_PASSWORD {
        return Err(error::cannot_unbind_password());
    }

    let count = IdentityRepo::count_by_user(&state.db, user_id).await?;
    if count <= 1 {
        return Err(error::must_keep_one_login_method());
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

pub async fn issue_tokens(state: &AppState, user: &User) -> Result<TokenResponse, AppError> {
    let user_id_str = user.id.to_string();
    let roles = vec![DEFAULT_ROLE.to_string()];

    let access_token = jwt::sign_access_token(
        &user_id_str,
        roles,
        &state.jwt_keys,
        state.config.jwt.access_ttl_minutes,
        None,
        None,
        None,
    )?;

    let (_, refresh_token) =
        session::create_session(&state.cache, user.id, state.config.jwt.refresh_ttl_days).await?;

    Ok(TokenResponse {
        access_token,
        refresh_token,
        user: user.clone().into(),
    })
}

pub async fn validate_new_user<'a, E>(
    executor: E,
    username: &str,
    email: &str,
) -> Result<(), AppError>
where
    E: sqlx::Executor<'a, Database = sqlx::Postgres>,
{
    #[derive(sqlx::FromRow)]
    struct Check {
        username_exists: bool,
        email_exists: bool,
    }
    let check: Check = sqlx::query_as(
        "SELECT EXISTS(SELECT 1 FROM users WHERE username = $1) AS username_exists, EXISTS(SELECT 1 FROM users WHERE email = $2) AS email_exists"
    )
    .bind(username)
    .bind(email)
    .fetch_one(executor)
    .await?;
    if check.username_exists {
        return Err(error::username_exists(username));
    }
    if check.email_exists {
        return Err(error::email_exists(email));
    }
    Ok(())
}

pub async fn validate_update_user<'a, E>(
    executor: E,
    id: Uuid,
    username: Option<&str>,
    email: Option<&str>,
) -> Result<(), AppError>
where
    E: sqlx::Executor<'a, Database = sqlx::Postgres>,
{
    #[derive(sqlx::FromRow)]
    struct Check {
        username_conflict: bool,
        email_conflict: bool,
    }
    let check: Check = sqlx::query_as(
        "SELECT EXISTS(SELECT 1 FROM users WHERE username = $1 AND id != $3) AS username_conflict, EXISTS(SELECT 1 FROM users WHERE email = $2 AND id != $3) AS email_conflict"
    )
    .bind(username)
    .bind(email)
    .bind(id)
    .fetch_one(executor)
    .await?;
    if check.username_conflict {
        return Err(error::username_exists(username.unwrap()));
    }
    if check.email_conflict {
        return Err(error::email_exists(email.unwrap()));
    }
    Ok(())
}

pub fn hash_password(password: &str) -> Result<String, AppError> {
    bcrypt::hash(password, bcrypt::DEFAULT_COST)
        .map_err(|e| AppError::Internal(format!("Password hash error: {e}")))
}

pub async fn create_user_with_password(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    username: &str,
    email: &str,
    phone: Option<&str>,
    nickname: Option<&str>,
    password: &str,
) -> Result<User, AppError> {
    let password_hash = hash_password(password)?;
    validate_new_user(&mut **tx, username, email).await?;
    let user = UserRepo::create(&mut **tx, username, email, phone, nickname).await?;
    IdentityRepo::create_password(&mut **tx, user.id, &password_hash).await?;
    Ok(user)
}
