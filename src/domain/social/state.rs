use sqlx::postgres::PgPool;

use crate::infra::cache::Pool;

#[derive(Clone)]
pub struct SocialState {
    pub db: PgPool,
    pub cache: Pool,
    pub oidc_issuer: String,
}
