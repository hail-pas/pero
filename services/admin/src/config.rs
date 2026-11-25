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
        &["oauth2.scopes"]
    }
}

impl Validatable for AppConfig {
    fn validate(&self) -> ValidationResult {
        self.server.validate()?;
        self.oauth2.validate()?;
        self.cookie.validate()?;
        pero_validate_core::ensure(
            self.cookie.secure
                || reqwest::Url::parse(&self.oauth2.redirect_uri)
                    .is_ok_and(|url| url.scheme() == "http"),
            "cookie.secure",
            "https_requires_secure_cookie",
            "cookie.secure must be true for an HTTPS redirect URI",
        )?;
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
        pero_validate_core::ensure(
            pero_utils::redirect::is_valid_service_base_url(&self.issuer),
            "oauth2.issuer",
            "invalid_url",
            "oauth2.issuer must be an absolute HTTPS URL without a query or fragment (loopback HTTP is allowed)",
        )?;
        pero_validate_core::not_blank(&self.client_id, "oauth2.client_id")?;
        pero_validate_core::ensure(
            !self.client_secret.expose_secret().trim().is_empty()
                && self.client_secret.expose_secret() != "CHANGE_ME",
            "oauth2.client_secret",
            "required",
            "oauth2.client_secret must be configured with the registered client secret",
        )?;
        for (uri, field) in [
            (&self.redirect_uri, "oauth2.redirect_uri"),
            (&self.post_logout_redirect_uri, "oauth2.post_logout_redirect_uri"),
        ] {
            pero_validate_core::ensure(
                pero_utils::redirect::validate_oauth_redirect_uri(uri, false).is_ok(),
                field,
                "invalid_url",
                "redirect URI must be an absolute HTTPS URL (loopback HTTP is allowed)",
            )?;
        }
        pero_validate_core::ensure(
            self.scopes.iter().any(|scope| scope == "openid"),
            "oauth2.scopes",
            "required",
            "oauth2.scopes must include openid",
        )?;
        pero_validate_core::min(
            self.jwks_cache_ttl_seconds,
            60,
            "oauth2.jwks_cache_ttl_seconds",
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn https_redirect_requires_secure_cookies() {
        let mut config: AppConfig = serde_json::from_value(serde_json::json!({
            "oauth2": {"client_id": "test-client", "client_secret": "test-secret"}
        }))
        .unwrap();
        assert!(config.validate().is_ok());

        config.oauth2.redirect_uri = "https://admin.example.test/callback".into();
        assert!(config.validate().is_err());

        config.cookie.secure = true;
        assert!(config.validate().is_ok());
    }
}
