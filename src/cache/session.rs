use redis::aio::ConnectionManager;
use crate::cache;
use crate::shared::error::AppError;

const REFRESH_TOKEN_PREFIX: &str = "refresh_token:";

pub async fn store_refresh_token(
    conn: &mut ConnectionManager,
    user_id: &str,
    token: &str,
    ttl_days: i64,
) -> Result<(), AppError> {
    let key = format!("{REFRESH_TOKEN_PREFIX}{user_id}");
    let ttl_seconds = ttl_days * 86400;
    cache::set(conn, &key, token, ttl_seconds).await
}

pub async fn get_refresh_token(
    conn: &mut ConnectionManager,
    user_id: &str,
) -> Result<Option<String>, AppError> {
    let key = format!("{REFRESH_TOKEN_PREFIX}{user_id}");
    cache::get(conn, &key).await
}

pub async fn revoke_refresh_token(
    conn: &mut ConnectionManager,
    user_id: &str,
) -> Result<(), AppError> {
    let key = format!("{REFRESH_TOKEN_PREFIX}{user_id}");
    cache::del(conn, &key).await
}
