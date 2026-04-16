use crate::cache;
use crate::shared::constants::cache_keys;
use crate::shared::error::AppError;
use crate::cache::Pool;

pub async fn store_refresh_token(
    pool: &Pool,
    user_id: &str,
    token: &str,
    ttl_days: i64,
) -> Result<(), AppError> {
    let key = format!("{}{user_id}", cache_keys::REFRESH_TOKEN_PREFIX);
    let ttl_seconds = ttl_days * 86400;
    cache::set(pool, &key, token, ttl_seconds).await
}

pub async fn get_refresh_token(
    pool: &Pool,
    user_id: &str,
) -> Result<Option<String>, AppError> {
    let key = format!("{}{user_id}", cache_keys::REFRESH_TOKEN_PREFIX);
    cache::get(pool, &key).await
}

pub async fn store_previous_refresh_token(
    pool: &Pool,
    user_id: &str,
    token: &str,
    ttl_days: i64,
) -> Result<(), AppError> {
    let key = format!("{}{user_id}", cache_keys::REFRESH_TOKEN_PREV_PREFIX);
    let ttl_seconds = ttl_days * 86400;
    cache::set(pool, &key, token, ttl_seconds).await
}

pub async fn get_previous_refresh_token(
    pool: &Pool,
    user_id: &str,
) -> Result<Option<String>, AppError> {
    let key = format!("{}{user_id}", cache_keys::REFRESH_TOKEN_PREV_PREFIX);
    cache::get(pool, &key).await
}

pub async fn revoke_refresh_token(
    pool: &Pool,
    user_id: &str,
) -> Result<(), AppError> {
    let key = format!("{}{user_id}", cache_keys::REFRESH_TOKEN_PREFIX);
    cache::del(pool, &key).await?;
    let prev_key = format!("{}{user_id}", cache_keys::REFRESH_TOKEN_PREV_PREFIX);
    let _ = cache::del(pool, &prev_key).await;
    Ok(())
}
