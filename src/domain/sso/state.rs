use std::sync::Arc;

use sqlx::postgres::PgPool;

use crate::config::SsoConfig;
use crate::infra::cache::Pool;
use crate::infra::jwt::JwtKeys;

#[derive(Clone)]
pub struct SsoState {
    pub db: PgPool,
    pub cache: Pool,
    pub jwt_keys: Arc<JwtKeys>,
    pub config: Arc<SsoConfig>,
}
