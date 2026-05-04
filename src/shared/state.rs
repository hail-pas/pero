use crate::config::AppConfig;
use crate::domain::abac::repo::{AbacCacheStore, AbacStore};
use crate::domain::app::repo::AppStore;
use crate::domain::auth::repo::SessionStore;
use crate::domain::credential::repo::IdentityStore;
use crate::domain::federation::http::HttpClient;
use crate::domain::federation::repo::SocialStore;
use crate::domain::oauth::repo::{
    AuthorizationCodeStore, OAuth2ClientStore, RefreshTokenStore, TokenFamilyStore, TokenSigner,
};
use crate::domain::sso::repo::SsoSessionStore;
use crate::domain::user::repo::{UserAttributeStore, UserStore};
use crate::infra::jwt::JwtKeys;
use crate::shared::kv::KvStore;
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
    pub auth_codes: Arc<dyn AuthorizationCodeStore>,
    pub token_families: Arc<dyn TokenFamilyStore>,
    pub refresh_tokens: Arc<dyn RefreshTokenStore>,
    pub social: Arc<dyn SocialStore>,
    pub apps: Arc<dyn AppStore>,
    pub kv: Arc<dyn KvStore>,
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
