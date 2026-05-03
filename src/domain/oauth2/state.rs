use std::sync::Arc;

use sqlx::postgres::PgPool;

use crate::config::OAuth2Config;
use crate::infra::cache::Pool;
use crate::infra::jwt::JwtKeys;

#[derive(Clone)]
pub struct OAuth2State {
    pub db: PgPool,
    pub cache: Pool,
    pub jwt_keys: Arc<JwtKeys>,
    pub config: Arc<OAuth2Config>,
}
