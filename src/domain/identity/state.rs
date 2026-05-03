use std::sync::Arc;

use sqlx::postgres::PgPool;

use crate::config::JwtConfig;
use crate::infra::cache::Pool;

#[derive(Clone)]
pub struct IdentityState {
    pub db: PgPool,
    pub cache: Pool,
    pub jwt_config: Arc<JwtConfig>,
}
