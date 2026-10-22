use std::sync::Arc;

use pero_cache_redis::RedisCacheStore;
use pero_http_client_core::{HttpClient, HttpClientHandle};
use sea_orm::DatabaseConnection;

use crate::config::AppConfig;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<AppConfig>,
    pub db: DatabaseConnection,
    pub cache: Arc<RedisCacheStore>,
    pub http_client: HttpClientHandle,
    pub signing_keys: Arc<super::signing_key::SigningKeyCache>,
    pub upstream_jwks: Arc<crate::service::social::JwksCache>,
}

impl AppState {
    pub fn new(
        config: AppConfig,
        db: DatabaseConnection,
        cache: RedisCacheStore,
        http_client: impl HttpClient + 'static,
    ) -> Self {
        Self {
            config: Arc::new(config),
            db,
            cache: Arc::new(cache),
            http_client: Arc::new(http_client),
            signing_keys: Arc::default(),
            upstream_jwks: Arc::default(),
        }
    }

    pub fn session_service(&self) -> crate::service::session::SessionService<'_> {
        crate::service::session::SessionService::new(&self.db, &self.config.sso)
    }

    pub fn oauth_service(&self) -> crate::service::oauth::OAuthService<'_> {
        crate::service::oauth::OAuthService::new(&self.db, &self.cache, &self.config.oauth2)
    }

    pub fn social_service(&self) -> crate::service::social::SocialLoginService<'_> {
        crate::service::social::SocialLoginService::new(
            &self.db,
            &self.cache,
            &self.http_client,
            &self.config.sso,
            &self.config.oauth2,
            &self.upstream_jwks,
        )
    }

    pub fn web_security(&self) -> crate::web::security::SsoWebSecurity<'_> {
        crate::web::security::SsoWebSecurity::new(&self.config.sso)
    }

    pub fn cookie_factory(&self) -> crate::web::security::SsoCookieFactory<'_> {
        crate::web::security::SsoCookieFactory::new(&self.config.sso)
    }
}
