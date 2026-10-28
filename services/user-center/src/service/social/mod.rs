mod adapter;
mod helper;
mod jwks;
mod link;
mod oauth2_adapter;
mod oidc;
pub use jwks::JwksCache;
mod service_impl;
mod wechat_adapter;

#[cfg(test)]
mod adapter_tests;

pub use adapter::{ExchangeCodeParams, TokenResult};

use pero_cache_redis::RedisCacheStore;
use pero_http_client_core::HttpClientHandle;
use sea_orm::DatabaseConnection;
use uuid::Uuid;

use crate::db::entity::users;
use crate::db::helper::provider::ProviderWithSecret;

pub struct SocialLoginService<'a> {
    db: &'a DatabaseConnection,
    cache: &'a RedisCacheStore,
    http_client: &'a HttpClientHandle,
    jwks: &'a JwksCache,
    sso_config: &'a crate::config::SsoConfig,
    oauth2_config: &'a crate::config::OAuth2Config,
}

pub enum SocialLoginError {
    ProviderNotFound,
    ProviderMisconfigured,
    InvalidState,
    TokenExchangeFailed(String),
    UserinfoFailed(String),
    Internal(String),
    Dependency(pero_error::AppError),
}

pub enum IdentityResolution {
    Resolved {
        user: users::Model,
        identity_id: Uuid,
    },
    NeedsAccountLink {
        nonce: String,
    },
    NeedsRegistration {
        info: SocialUserInfo,
        auth_request_id: Option<Uuid>,
    },
}

pub struct SocialUserInfo {
    pub authenticated_at: Option<time::OffsetDateTime>,
    pub sub: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub name: Option<String>,
    pub avatar_url: Option<String>,
    pub profile_extra: serde_json::Value,
}

impl SocialUserInfo {
    fn profile(&self) -> serde_json::Value {
        let mut profile = serde_json::json!({
            "email": self.email,
            "email_verified": self.email_verified,
            "name": self.name,
            "picture": self.avatar_url,
        });
        if let (serde_json::Value::Object(fields), serde_json::Value::Object(extra)) =
            (&mut profile, &self.profile_extra)
        {
            fields.extend(extra.clone());
        }
        profile
    }
}

pub enum SocialLinkError {
    ReauthenticationRequired,
    InvalidSession,
    ProviderAlreadyLinked,
    IdentityTaken,
    Internal(String),
}

pub struct PreparedLoginState {
    pub state_token: String,
    pub state_hash: String,
    pub authorize_url: String,
}

pub struct ValidatedCallbackState {
    pub social_value: crate::cache::key::SocialStateValue,
    pub provider: ProviderWithSecret,
    pub auth_request_id: Option<Uuid>,
}
