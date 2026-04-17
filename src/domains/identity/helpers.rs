use crate::cache::session;
use crate::domains::identity::models::{TokenResponse, User};
use crate::domains::identity::repos::{IdentityRepo, UserRepo};
use crate::shared::constants::identity::DEFAULT_ROLE;
use crate::shared::error::AppError;
use crate::shared::jwt;
use crate::shared::state::AppState;
use uuid::Uuid;

pub async fn issue_tokens(state: &AppState, user: &User) -> Result<TokenResponse, AppError> {
    let user_id_str = user.id.to_string();
    let roles = vec![DEFAULT_ROLE.to_string()];

    let access_token = jwt::sign_access_token(
        &user_id_str,
        roles,
        &state.jwt_keys,
        state.config.jwt.access_ttl_minutes,
        None,
    )?;

    let refresh_token = format!("{}:{}", user.id, uuid::Uuid::new_v4());
    session::store_refresh_token(
        &state.cache,
        &user_id_str,
        &refresh_token,
        state.config.jwt.refresh_ttl_days,
    )
    .await?;

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
        return Err(AppError::Conflict(format!(
            "username '{}' already exists",
            username
        )));
    }
    if check.email_exists {
        return Err(AppError::Conflict(format!(
            "email '{}' already exists",
            email
        )));
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
        return Err(AppError::Conflict(format!(
            "username '{}' already exists",
            username.unwrap()
        )));
    }
    if check.email_conflict {
        return Err(AppError::Conflict(format!(
            "email '{}' already exists",
            email.unwrap()
        )));
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
