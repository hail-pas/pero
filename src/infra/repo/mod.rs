pub mod abac;
pub mod app;
pub mod auth_code;
pub mod credential;
pub mod kv;
pub mod oauth_client;
pub mod refresh_token;
pub mod session;
pub mod social;
pub mod sso_session;
pub mod token_family;
pub mod user;
pub mod user_attrs;

pub use abac::{RedisAbacCacheStore, SqlxAbacStore};
pub use app::SqlxAppStore;
pub use auth_code::SqlxAuthCodeStore;
pub use credential::SqlxIdentityStore;
pub use kv::RedisKvStore;
pub use oauth_client::{JwtTokenSigner, SqlxOAuth2ClientStore};
pub use refresh_token::SqlxRefreshTokenStore;
pub use session::RedisSessionStore;
pub use social::SqlxSocialStore;
pub use sso_session::RedisSsoSessionStore;
pub use token_family::SqlxTokenFamilyStore;
pub use user::SqlxUserStore;
pub use user_attrs::SqlxUserAttributeStore;

use crate::config::AppConfig;
use crate::domain::federation::http::HttpClient;
use crate::infra::cache;
use crate::infra::http::client::ReqwestHttpClient;
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
        auth_codes: Arc::new(SqlxAuthCodeStore::new(db.clone())),
        token_families: Arc::new(SqlxTokenFamilyStore::new(db.clone())),
        refresh_tokens: Arc::new(SqlxRefreshTokenStore::new(db.clone())),
        social: Arc::new(SqlxSocialStore::new(db.clone())),
        apps: Arc::new(SqlxAppStore::new(db)),
        kv: Arc::new(RedisKvStore::new(cache_pool)),
        http: Arc::new(ReqwestHttpClient) as Arc<dyn HttpClient>,
        token_signer: Arc::new(JwtTokenSigner::new(
            jwt_keys,
            cfg.oauth2.access_token_ttl_minutes,
            cfg.oidc.issuer.clone(),
        )),
    }
}
