use crate::cache;
use crate::cache::Pool;
use crate::shared::constants::cache_keys;
use crate::shared::error::AppError;

const SECONDS_PER_DAY: i64 = 86400;

async fn store_token(
    pool: &Pool,
    prefix: &str,
    user_id: &str,
    token: &str,
    ttl_days: i64,
) -> Result<(), AppError> {
    let key = format!("{prefix}{user_id}");
    cache::set(pool, &key, token, ttl_days * SECONDS_PER_DAY).await
}

async fn get_token(pool: &Pool, prefix: &str, user_id: &str) -> Result<Option<String>, AppError> {
    let key = format!("{prefix}{user_id}");
    cache::get(pool, &key).await
}

pub async fn store_refresh_token(
    pool: &Pool,
    user_id: &str,
    token: &str,
    ttl_days: i64,
) -> Result<(), AppError> {
    store_token(
        pool,
        cache_keys::REFRESH_TOKEN_PREFIX,
        user_id,
        token,
        ttl_days,
    )
    .await
}

pub async fn get_refresh_token(pool: &Pool, user_id: &str) -> Result<Option<String>, AppError> {
    get_token(pool, cache_keys::REFRESH_TOKEN_PREFIX, user_id).await
}

pub async fn store_previous_refresh_token(
    pool: &Pool,
    user_id: &str,
    token: &str,
    ttl_days: i64,
) -> Result<(), AppError> {
    store_token(
        pool,
        cache_keys::REFRESH_TOKEN_PREV_PREFIX,
        user_id,
        token,
        ttl_days,
    )
    .await
}

pub async fn get_previous_refresh_token(
    pool: &Pool,
    user_id: &str,
) -> Result<Option<String>, AppError> {
    get_token(pool, cache_keys::REFRESH_TOKEN_PREV_PREFIX, user_id).await
}

pub async fn revoke_refresh_token(pool: &Pool, user_id: &str) -> Result<(), AppError> {
    let key = format!("{}{user_id}", cache_keys::REFRESH_TOKEN_PREFIX);
    cache::del(pool, &key).await?;
    let prev_key = format!("{}{user_id}", cache_keys::REFRESH_TOKEN_PREV_PREFIX);
    if let Err(e) = cache::del(pool, &prev_key).await {
        tracing::warn!(error = %e, "failed to delete previous refresh token during revocation");
    }
    Ok(())
}
