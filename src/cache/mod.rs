pub mod session;

use redis::aio::ConnectionManager;
use redis::Client;
use crate::config::RedisConfig;
use crate::error::AppError;

pub async fn init_pool(cfg: &RedisConfig) -> Result<ConnectionManager, AppError> {
    let client = Client::open(cfg.url.as_str())
        .map_err(|e| AppError::Internal(format!("Redis client init failed: {e}")))?;

    let conn = ConnectionManager::new(client)
        .await
        .map_err(|e| AppError::Internal(format!("Redis connection failed: {e}")))?;

    tracing::info!("Redis connected: {}", cfg.url);
    Ok(conn)
}

pub async fn get(conn: &mut ConnectionManager, key: &str) -> Result<Option<String>, AppError> {
    let result: Option<String> = redis::cmd("GET")
        .arg(key)
        .query_async(conn)
        .await?;
    Ok(result)
}

pub async fn set(conn: &mut ConnectionManager, key: &str, value: &str, ttl_seconds: i64) -> Result<(), AppError> {
    redis::cmd("SET")
        .arg(key)
        .arg(value)
        .arg("EX")
        .arg(ttl_seconds)
        .query_async::<()>(conn)
        .await?;
    Ok(())
}

pub async fn del(conn: &mut ConnectionManager, key: &str) -> Result<(), AppError> {
    redis::cmd("DEL")
        .arg(key)
        .query_async::<()>(conn)
        .await?;
    Ok(())
}
