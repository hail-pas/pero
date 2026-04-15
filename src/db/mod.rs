pub mod repos;

use sqlx::postgres::{PgPool, PgPoolOptions};
use crate::config::DatabaseConfig;
use crate::shared::error::AppError;

pub async fn init_pool(cfg: &DatabaseConfig) -> Result<PgPool, AppError> {
    let pool = PgPoolOptions::new()
        .max_connections(cfg.max_connections)
        .min_connections(cfg.min_connections)
        .connect(&cfg.url)
        .await
        .map_err(|e| AppError::Internal(format!("Database connection failed: {e}")))?;

    sqlx::query("SELECT 1")
        .execute(&pool)
        .await
        .map_err(|e| AppError::Internal(format!("Database health check failed: {e}")))?;

    tracing::info!("Database connected: {}", cfg.url.split('@').last().unwrap_or("*****"));
    Ok(pool)
}
