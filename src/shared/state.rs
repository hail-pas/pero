use crate::config::AppConfig;
use crate::shared::jwt::JwtKeys;
use redis::aio::ConnectionManager;
use sqlx::postgres::PgPool;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub cache: ConnectionManager,
    pub config: Arc<AppConfig>,
    pub jwt_keys: Arc<JwtKeys>,
}
