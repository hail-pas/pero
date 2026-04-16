pub mod session;

use crate::config::RedisConfig;
use crate::shared::error::AppError;
use redis::Client;
use redis::aio::ConnectionManager;

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
    let result: Option<String> = redis::cmd("GET").arg(key).query_async(conn).await?;
    Ok(result)
}

pub async fn set(
    conn: &mut ConnectionManager,
    key: &str,
    value: &str,
    ttl_seconds: i64,
) -> Result<(), AppError> {
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
    redis::cmd("DEL").arg(key).query_async::<()>(conn).await?;
    Ok(())
}

pub async fn get_json<T: serde::de::DeserializeOwned>(
    conn: &mut ConnectionManager,
    key: &str,
) -> Result<Option<T>, AppError> {
    let raw = get(conn, key).await?;
    match raw {
        Some(json_str) => {
            let val: T = serde_json::from_str(&json_str)
                .map_err(|e| AppError::Internal(format!("cache deserialize error: {e}")))?;
            Ok(Some(val))
        }
        None => Ok(None),
    }
}

pub async fn set_json<T: serde::Serialize>(
    conn: &mut ConnectionManager,
    key: &str,
    value: &T,
    ttl_seconds: i64,
) -> Result<(), AppError> {
    let json_str = serde_json::to_string(value)
        .map_err(|e| AppError::Internal(format!("cache serialize error: {e}")))?;
    set(conn, key, &json_str, ttl_seconds).await
}
