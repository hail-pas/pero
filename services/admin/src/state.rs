use std::sync::Arc;
use std::time::Duration;

use crate::config::AppConfig;
use crate::oauth2::JwksCache;

#[derive(Debug, Clone)]
pub struct AppState {
    pub config: Arc<AppConfig>,
    pub http: reqwest::Client,
    pub jwks: JwksCache,
}

impl AppState {
    pub fn new(config: AppConfig) -> Self {
        let http = pero_http_client_reqwest::ReqwestHttpClient::from_config(
            &pero_http_client_core::HttpClientConfig::default(),
        )
        .expect("failed to create HTTP client")
        .inner()
        .clone();
        let jwks = JwksCache::new(Duration::from_secs(config.oauth2.jwks_cache_ttl_seconds));
        Self {
            config: Arc::new(config),
            http,
            jwks,
        }
    }
}
