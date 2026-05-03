use crate::config::AppConfig;
use crate::domain::abac::repo::{AbacCacheStore, AbacStore};
use crate::domain::app::repo::AppStore;
use crate::domain::identity::repo::{IdentityStore, SessionStore, UserAttributeStore, UserStore};
use crate::domain::oauth2::repo::{OAuth2ClientStore, OAuth2TokenStore, TokenSigner};
use crate::domain::social::http::HttpClient;
use crate::domain::social::repo::SocialStore;
use crate::domain::sso::repo::SsoSessionStore;
use crate::infra::jwt::JwtKeys;
use crate::infra::repo::kv::RedisKvStore;
use serde_json::Value;
use std::sync::{Arc, OnceLock};

#[derive(Clone)]
pub struct Repos {
    pub users: Arc<dyn UserStore>,
    pub identities: Arc<dyn IdentityStore>,
    pub user_attributes: Arc<dyn UserAttributeStore>,
    pub sessions: Arc<dyn SessionStore>,
    pub sso_sessions: Arc<dyn SsoSessionStore>,
    pub policies: Arc<dyn AbacStore>,
    pub abac_cache: Arc<dyn AbacCacheStore>,
    pub oauth2_clients: Arc<dyn OAuth2ClientStore>,
    pub oauth2_tokens: Arc<dyn OAuth2TokenStore>,
    pub social: Arc<dyn SocialStore>,
    pub apps: Arc<dyn AppStore>,
    pub kv: Arc<RedisKvStore>,
    pub http: Arc<dyn HttpClient>,
    pub token_signer: Arc<dyn TokenSigner>,
}

#[derive(Clone)]
pub struct AppState {
    pub repos: Arc<Repos>,
    pub jwt_keys: Arc<JwtKeys>,
    pub config: Arc<AppConfig>,
    pub discovery_doc: Arc<OnceLock<Value>>,
    pub jwks_doc: Arc<OnceLock<Value>>,
}
