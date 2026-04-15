use std::sync::Arc;
use redis::aio::ConnectionManager;
use sqlx::postgres::PgPool;
use crate::config::AppConfig;

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub cache: ConnectionManager,
    pub config: Arc<AppConfig>,
}
