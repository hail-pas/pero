pub mod session;

use std::fs;

use crate::config::RedisConfig;
use crate::shared::error::AppError;
use redis::Client;
use redis::TlsCertificates;
use redis::aio::ConnectionManager;

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

pub async fn init_pool(cfg: &RedisConfig) -> Result<ConnectionManager, AppError> {
    let ssl_ca_certs = url::Url::parse(&cfg.url).ok().and_then(|u| {
        u.query_pairs()
            .find(|(k, _)| k == "ssl_ca_certs")
            .map(|(_, v)| v.into_owned())
    });

    let client = if let Some(ca_path) = ssl_ca_certs {
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
        .map_err(|e| AppError::Internal(format!("Redis client init failed: {e}")))?
    } else {
        Client::open(cfg.url.as_str())
            .map_err(|e| AppError::Internal(format!("Redis client init failed: {e}")))?
    };

    let conn = ConnectionManager::new(client)
        .await
        .map_err(|e| AppError::Internal(format!("Redis connection failed: {e}")))?;

    tracing::info!("Redis connected");
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
