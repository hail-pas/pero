pub mod abac;
pub mod app;
pub mod identity;
pub mod kv;
pub mod oauth2;
pub mod session;
pub mod social;
pub mod sso_session;

pub use abac::{RedisAbacCacheStore, SqlxAbacStore};
pub use app::SqlxAppStore;
pub use identity::{SqlxIdentityStore, SqlxUserAttributeStore, SqlxUserStore};
pub use kv::RedisKvStore;
pub use oauth2::{JwtTokenSigner, SqlxOAuth2ClientStore, SqlxOAuth2TokenStore};
pub use session::RedisSessionStore;
pub use social::SqlxSocialStore;
pub use sso_session::RedisSsoSessionStore;

use crate::config::AppConfig;
use crate::infra::cache;
use crate::infra::jwt::JwtKeys;
use crate::shared::state::Repos;
use sqlx::postgres::PgPool;
use std::sync::Arc;

pub fn build_repos(
    db: PgPool,
    cache_pool: cache::Pool,
    jwt_keys: Arc<JwtKeys>,
    cfg: &AppConfig,
) -> Repos {
    let db = Arc::new(db);
    Repos {
        users: Arc::new(SqlxUserStore::new(db.clone())),
        identities: Arc::new(SqlxIdentityStore::new(db.clone())),
        user_attributes: Arc::new(SqlxUserAttributeStore::new(db.clone())),
        sessions: Arc::new(RedisSessionStore::new(cache_pool.clone())),
        sso_sessions: Arc::new(RedisSsoSessionStore::new(cache_pool.clone())),
        policies: Arc::new(SqlxAbacStore::new(db.clone())),
        abac_cache: Arc::new(RedisAbacCacheStore::new(cache_pool.clone())),
        oauth2_clients: Arc::new(SqlxOAuth2ClientStore::new(db.clone())),
        oauth2_tokens: Arc::new(SqlxOAuth2TokenStore::new(db.clone())),
        social: Arc::new(SqlxSocialStore::new(db.clone())),
        apps: Arc::new(SqlxAppStore::new(db)),
        kv: Arc::new(RedisKvStore::new(cache_pool)),
        token_signer: Arc::new(JwtTokenSigner::new(jwt_keys, cfg.oauth2.access_token_ttl_minutes, cfg.oidc.issuer.clone())),
    }
}
