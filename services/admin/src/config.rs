use pero_config::ParseConfigurable;
use pero_config::blocks::FrontendConfig;
use pero_config::blocks::{CookieConfig, LogConfig, ServerConfig};
use pero_types::SecretString;
use pero_validate_core::{Validatable, ValidationResult};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub log: LogConfig,
    pub oauth2: OAuth2Config,
    #[serde(default)]
    pub cookie: CookieConfig,
    #[serde(default)]
    pub frontend: FrontendConfig,
}

impl ParseConfigurable for AppConfig {
    fn env_list_parse_keys() -> &'static [&'static str] {
        &[]
    }
}

impl Validatable for AppConfig {
    fn validate(&self) -> ValidationResult {
        self.server.validate()?;
        self.oauth2.validate()?;
        self.cookie.validate()?;
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct OAuth2Config {
    pub issuer: String,
    pub client_id: String,
    pub client_secret: SecretString,
    pub redirect_uri: String,
    pub post_logout_redirect_uri: String,
    pub scopes: Vec<String>,
    pub jwks_cache_ttl_seconds: u64,
}

impl Default for OAuth2Config {
    fn default() -> Self {
        Self {
            issuer: "http://localhost:8080".to_owned(),
            client_id: String::new(),
            client_secret: SecretString::default(),
            redirect_uri: "http://localhost:3000/callback".to_owned(),
            post_logout_redirect_uri: "http://localhost:3000".to_owned(),
            scopes: vec![
                "openid".to_owned(),
                "profile".to_owned(),
                "email".to_owned(),
            ],
            jwks_cache_ttl_seconds: 3600,
        }
    }
}

impl Validatable for OAuth2Config {
    fn validate(&self) -> ValidationResult {
        pero_validate_core::not_blank(&self.issuer, "oauth2.issuer")?;
        pero_validate_core::not_blank(&self.client_id, "oauth2.client_id")?;
        pero_validate_core::ensure(
            !self.client_secret.is_empty(),
            "oauth2.client_secret",
            "required",
            "oauth2.client_secret is required",
        )?;
        pero_validate_core::not_blank(&self.redirect_uri, "oauth2.redirect_uri")?;
        pero_validate_core::min(
            self.jwks_cache_ttl_seconds,
            60,
            "oauth2.jwks_cache_ttl_seconds",
        )?;
        Ok(())
    }
}
