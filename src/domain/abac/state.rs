use std::sync::Arc;

use sqlx::postgres::PgPool;

use crate::config::AbacConfig;
use crate::infra::cache::Pool;

#[derive(Clone)]
pub struct AbacState {
    pub db: PgPool,
    pub cache: Pool,
    pub config: Arc<AbacConfig>,
}
