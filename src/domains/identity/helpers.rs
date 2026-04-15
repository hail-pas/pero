use crate::cache::session;
use crate::domains::identity::models::User;
use crate::domains::identity::models::TokenResponse;
use crate::domains::identity::repos::UserRepo;
use crate::shared::error::AppError;
use crate::shared::jwt;
use crate::shared::state::AppState;
use sqlx::postgres::PgPool;

pub async fn issue_tokens(
    state: &AppState,
    user: &User,
) -> Result<TokenResponse, AppError> {
    let user_id_str = user.id.to_string();
    let roles = vec!["user".to_string()];

    let access_token = jwt::sign_access_token(
        &user_id_str,
        roles,
        &state.jwt_keys,
        state.config.jwt.access_ttl_minutes,
    )?;

    let refresh_token = format!("{}:{}", user.id, uuid::Uuid::new_v4());
    session::store_refresh_token(
        &mut state.cache.clone(),
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

pub async fn validate_new_user(
    pool: &PgPool,
    username: &str,
    email: &str,
) -> Result<(), AppError> {
    if UserRepo::find_by_username(pool, username).await?.is_some() {
        return Err(AppError::Conflict(format!(
            "username '{}' already exists",
            username
        )));
    }
    if UserRepo::find_by_email(pool, email).await?.is_some() {
        return Err(AppError::Conflict(format!(
            "email '{}' already exists",
            email
        )));
    }
    Ok(())
}

pub fn hash_password(password: &str) -> Result<String, AppError> {
    bcrypt::hash(password, bcrypt::DEFAULT_COST)
        .map_err(|e| AppError::Internal(format!("Password hash error: {e}")))
}
