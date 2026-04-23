use std::fs;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::config::RedisConfig;
use crate::shared::error::AppError;
use deadpool::managed;
use deadpool::managed::RecycleResult;
use redis::Client;
use redis::TlsCertificates;

fn build_clean_url(raw: &str) -> Result<String, AppError> {
    let mut url =
        url::Url::parse(raw).map_err(|e| AppError::Internal(format!("Invalid redis URL: {e}")))?;

    let keep: Vec<(String, String)> = url
        .query_pairs()
        .filter(|(k, _)| k != "ssl_ca_certs" && k != "ssl_cert_reqs")
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();

    url.query_pairs_mut().clear();
    if !keep.is_empty() {
        let mut q = url.query_pairs_mut();
        for (k, v) in &keep {
            q.append_pair(k, v);
        }
    }

    Ok(url.into())
}

fn build_client(cfg: &RedisConfig) -> Result<Client, AppError> {
    let ssl_ca_certs = url::Url::parse(&cfg.url).ok().and_then(|u| {
        u.query_pairs()
            .find(|(k, _)| k == "ssl_ca_certs")
            .map(|(_, v)| v.into_owned())
    });

    if let Some(ca_path) = ssl_ca_certs {
        let root_cert = fs::read(&ca_path)
            .map_err(|e| AppError::Internal(format!("Failed to read CA cert {}: {e}", ca_path)))?;
        let clean_url = build_clean_url(&cfg.url)?;
        Client::build_with_tls(
            clean_url.as_str(),
            TlsCertificates {
                client_tls: None,
                root_cert: Some(root_cert),
            },
        )
        .map_err(|e| AppError::Internal(format!("Redis client init failed: {e}")))
    } else {
        Client::open(cfg.url.as_str())
            .map_err(|e| AppError::Internal(format!("Redis client init failed: {e}")))
    }
}

pub type Pool = managed::Pool<RedisManager>;
pub type Connection = redis::aio::MultiplexedConnection;

pub struct RedisManager {
    client: Client,
    ping_counter: AtomicUsize,
}

impl RedisManager {
    pub fn new(client: Client) -> Self {
        Self {
            client,
            ping_counter: AtomicUsize::new(0),
        }
    }
}

impl managed::Manager for RedisManager {
    type Type = Connection;
    type Error = redis::RedisError;

    async fn create(&self) -> Result<Connection, Self::Error> {
        self.client.get_multiplexed_async_connection().await
    }

    async fn recycle(
        &self,
        conn: &mut Connection,
        _: &managed::Metrics,
    ) -> RecycleResult<redis::RedisError> {
        let ping = self
            .ping_counter
            .fetch_add(1, Ordering::Relaxed)
            .to_string();
        let response: String = redis::cmd("PING")
            .arg(&ping)
            .query_async(conn)
            .await
            .map_err(|e| managed::RecycleError::Message(std::borrow::Cow::Owned(e.to_string())))?;
        if response != ping {
            return Err(managed::RecycleError::Message(std::borrow::Cow::Borrowed(
                "PING response mismatch",
            )));
        }
        Ok(())
    }
}

pub async fn init_pool(cfg: &RedisConfig) -> Result<Pool, AppError> {
    let client = build_client(cfg)?;
    let manager = RedisManager::new(client);

    let pool = managed::Pool::builder(manager)
        .max_size(cfg.pool_size)
        .build()
        .map_err(|e| AppError::Internal(format!("Redis pool build error: {e}")))?;

    let conn = pool
        .get()
        .await
        .map_err(|e| AppError::Internal(format!("Redis connection health check failed: {e}")))?;
    drop(conn);

    tracing::info!("Redis connected (pool_size={})", cfg.pool_size);
    Ok(pool)
}

pub async fn with_conn(pool: &Pool) -> Result<managed::Object<RedisManager>, AppError> {
    pool.get()
        .await
        .map_err(|e| AppError::Internal(e.to_string()))
}

pub async fn get(pool: &Pool, key: &str) -> Result<Option<String>, AppError> {
    let mut conn = with_conn(pool).await?;
    let result: Option<String> = redis::cmd("GET").arg(key).query_async(&mut *conn).await?;
    Ok(result)
}

pub async fn set(pool: &Pool, key: &str, value: &str, ttl_seconds: i64) -> Result<(), AppError> {
    let mut conn = with_conn(pool).await?;
    redis::cmd("SET")
        .arg(key)
        .arg(value)
        .arg("EX")
        .arg(ttl_seconds)
        .query_async::<()>(&mut *conn)
        .await?;
    Ok(())
}

pub async fn del(pool: &Pool, key: &str) -> Result<(), AppError> {
    let mut conn = with_conn(pool).await?;
    redis::cmd("DEL")
        .arg(key)
        .query_async::<()>(&mut *conn)
        .await?;
    Ok(())
}

pub async fn get_json<T: serde::de::DeserializeOwned>(
    pool: &Pool,
    key: &str,
) -> Result<Option<T>, AppError> {
    let raw = get(pool, key).await?;
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
    pool: &Pool,
    key: &str,
    value: &T,
    ttl_seconds: i64,
) -> Result<(), AppError> {
    let json_str = serde_json::to_string(value)
        .map_err(|e| AppError::Internal(format!("cache serialize error: {e}")))?;
    set(pool, key, &json_str, ttl_seconds).await
}

pub async fn delete_by_pattern(pool: &Pool, pattern: &str) -> Result<(), AppError> {
    let mut conn = with_conn(pool).await?;
    let mut cursor: u64 = 0;
    loop {
        let (new_cursor, keys): (u64, Vec<String>) = redis::cmd("SCAN")
            .arg(cursor)
            .arg("MATCH")
            .arg(pattern)
            .arg("COUNT")
            .arg(100)
            .query_async(&mut *conn)
            .await?;
        if !keys.is_empty() {
            let _: () = redis::cmd("UNLINK")
                .arg(&keys)
                .query_async(&mut *conn)
                .await?;
        }
        cursor = new_cursor;
        if cursor == 0 {
            break;
        }
    }
    Ok(())
}
