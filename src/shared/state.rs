use crate::infra::cache::Pool;
use crate::config::AppConfig;
use crate::infra::jwt::JwtKeys;
use sqlx::postgres::PgPool;
use std::sync::{Arc, OnceLock};

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
    pub cache: Pool,
    pub config: Arc<AppConfig>,
    pub jwt_keys: Arc<JwtKeys>,
    pub discovery_doc: Arc<OnceLock<serde_json::Value>>,
    pub jwks_doc: Arc<OnceLock<serde_json::Value>>,
}
