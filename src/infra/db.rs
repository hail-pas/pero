use crate::config::DatabaseConfig;
use crate::shared::error::AppError;
use sqlx::postgres::{PgPool, PgPoolOptions};

pub async fn init_pool(cfg: &DatabaseConfig) -> Result<PgPool, AppError> {
    let pool = PgPoolOptions::new()
        .max_connections(cfg.max_connections)
        .min_connections(cfg.min_connections)
        .acquire_timeout(std::time::Duration::from_secs(10))
        .idle_timeout(std::time::Duration::from_secs(600))
        .max_lifetime(std::time::Duration::from_secs(1800))
        .connect(&cfg.url)
        .await
        .map_err(|e| AppError::Internal(format!("Database connection failed: {e}")))?;

    sqlx::query("SELECT 1")
        .execute(&pool)
        .await
        .map_err(|e| AppError::Internal(format!("Database health check failed: {e}")))?;

    let display_host = url::Url::parse(&cfg.url)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_string()))
        .unwrap_or_else(|| "*****".to_string());
    tracing::info!("Database connected: {}", display_host);
    Ok(pool)
}
