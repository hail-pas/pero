use pero_cache_redis::RedisConfig;
use pero_config::ParseConfigurable;
use pero_config::blocks::{AskamaConfig, I18nConfig, LogConfig, ServerConfig};
use pero_db_seaorm::DatabaseConfig;
use pero_http_client_core::HttpClientConfig;
use pero_types::SecretString;
use pero_validate_core::{Validatable, ValidationResult};
use serde::Deserialize;

pub const ENCRYPT_KEY_CONFIG_KEY: &str = "app.encrypt_key";
pub const SYSTEM_APP_CODE: &str = "user-center";
pub const DASHBOARD_PAGE_SIZE: u64 = 20;

#[derive(Debug, Clone, Deserialize)]
pub struct DatabaseExtras {
    pub encrypt_key: SecretString,
}

pub type UserCenterDatabaseConfig = DatabaseConfig<DatabaseExtras>;

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SsoConfig {
    pub session_cookie_name: String,
    pub session_ttl_seconds: u64,
    pub session_idle_ttl_seconds: u64,
    pub session_touch_interval_seconds: u64,
    pub cookie_secure: bool,
    pub cookie_same_site: String,
    pub cookie_domain: String,
    pub cookie_path: String,
    pub cookie_signing_secret: SecretString,
    pub base_url: String,
}

impl Default for SsoConfig {
    fn default() -> Self {
        Self {
            session_cookie_name: "pero_sso".to_owned(),
            session_ttl_seconds: 86400,
            session_idle_ttl_seconds: 1800,
            session_touch_interval_seconds: 0,
            cookie_secure: false,
            cookie_same_site: "Lax".to_owned(),
            cookie_domain: String::new(),
            cookie_path: "/".to_owned(),
            cookie_signing_secret: SecretString::new(""),
            base_url: "http://localhost:8080".to_owned(),
        }
    }
}

impl Validatable for SsoConfig {
    fn validate(&self) -> ValidationResult {
        pero_validate_core::not_blank(&self.session_cookie_name, "sso.session_cookie_name")?;
        pero_validate_core::min(self.session_ttl_seconds, 1, "sso.session_ttl_seconds")?;
        pero_validate_core::min(
            self.session_idle_ttl_seconds,
            1,
            "sso.session_idle_ttl_seconds",
        )?;
        pero_validate_core::ensure(
            self.session_touch_interval_seconds <= 30
                && self.session_touch_interval_seconds <= self.session_idle_ttl_seconds / 100,
            "sso.session_touch_interval_seconds",
            "range",
            "touch interval must not exceed 30 seconds or 1% of idle TTL",
        )?;
        pero_validate_core::not_blank(&self.cookie_same_site, "sso.cookie_same_site")?;
        pero_validate_core::one_of(
            &self.cookie_same_site.as_str(),
            &["Lax", "Strict", "None"],
            "sso.cookie_same_site",
        )?;
        pero_validate_core::ensure(
            self.cookie_same_site != "None" || self.cookie_secure,
            "sso.cookie_secure",
            "same_site_none_requires_secure",
            "sso.cookie_secure must be true when sso.cookie_same_site is None",
        )?;
        pero_validate_core::not_blank(&self.cookie_path, "sso.cookie_path")?;
        pero_validate_core::ensure(
            !self.cookie_signing_secret.is_empty(),
            "sso.cookie_signing_secret",
            "required",
            "sso.cookie_signing_secret must not be empty",
        )?;
        pero_validate_core::min_length(
            self.cookie_signing_secret.expose_secret(),
            32,
            "sso.cookie_signing_secret",
        )?;
        pero_validate_core::ensure(
            self.cookie_signing_secret.expose_secret() != "change-me-cookie-signing-key-32bytes!!",
            "sso.cookie_signing_secret",
            "weak_default",
            "sso.cookie_signing_secret must be changed from the default placeholder",
        )?;
        pero_validate_core::not_blank(&self.base_url, "sso.base_url")?;
        Ok(())
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct OidcConfig {
    pub issuer: String,
}

impl Validatable for OidcConfig {
    fn validate(&self) -> ValidationResult {
        pero_validate_core::not_blank(&self.issuer, "oidc.issuer")?;
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct OAuth2Config {
    pub upstream_jwks_cache_ttl_seconds: u64,
    pub auth_code_ttl_seconds: u64,
    pub default_access_token_ttl_seconds: u64,
    pub default_refresh_token_ttl_days: u32,
    pub default_id_token_ttl_seconds: u64,
}

impl Default for OAuth2Config {
    fn default() -> Self {
        Self {
            upstream_jwks_cache_ttl_seconds: 0,
            auth_code_ttl_seconds: 600,
            default_access_token_ttl_seconds: 7200,
            default_refresh_token_ttl_days: 30,
            default_id_token_ttl_seconds: 7200,
        }
    }
}

impl Validatable for OAuth2Config {
    fn validate(&self) -> ValidationResult {
        pero_validate_core::max(
            self.upstream_jwks_cache_ttl_seconds,
            300,
            "oauth2.upstream_jwks_cache_ttl_seconds",
        )?;
        pero_validate_core::min(
            self.auth_code_ttl_seconds,
            1,
            "oauth2.auth_code_ttl_seconds",
        )?;
        pero_validate_core::min(
            self.default_access_token_ttl_seconds,
            1,
            "oauth2.default_access_token_ttl_seconds",
        )?;
        pero_validate_core::min(
            self.default_refresh_token_ttl_days,
            1,
            "oauth2.default_refresh_token_ttl_days",
        )?;
        pero_validate_core::min(
            self.default_id_token_ttl_seconds,
            1,
            "oauth2.default_id_token_ttl_seconds",
        )?;
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PasswordConfig {
    pub min_length: u32,
    pub max_length: u32,
    pub require_uppercase: bool,
    pub require_lowercase: bool,
    pub require_digit: bool,
    pub require_special: bool,
}

impl Default for PasswordConfig {
    fn default() -> Self {
        Self {
            min_length: 8,
            max_length: 128,
            require_uppercase: true,
            require_lowercase: true,
            require_digit: true,
            require_special: false,
        }
    }
}

impl Validatable for PasswordConfig {
    fn validate(&self) -> ValidationResult {
        pero_validate_core::min(self.min_length, 1, "password.min_length")?;
        pero_validate_core::max(self.min_length, self.max_length, "password.min_length")?;
        Ok(())
    }
}

impl PasswordConfig {
    pub fn validate_password(&self, password: &str) -> Result<(), String> {
        let char_count = password.chars().count();
        if char_count < self.min_length as usize {
            return Err(format!(
                "password must be at least {} characters",
                self.min_length
            ));
        }
        if char_count > self.max_length as usize {
            return Err(format!(
                "password must be at most {} characters",
                self.max_length
            ));
        }
        if self.require_uppercase && !password.chars().any(|c| c.is_uppercase()) {
            return Err("password must contain an uppercase letter".to_owned());
        }
        if self.require_lowercase && !password.chars().any(|c| c.is_lowercase()) {
            return Err("password must contain a lowercase letter".to_owned());
        }
        if self.require_digit && !password.chars().any(|c| c.is_ascii_digit()) {
            return Err("password must contain a digit".to_owned());
        }
        if self.require_special && !password.chars().any(|c| !c.is_alphanumeric()) {
            return Err("password must contain a special character".to_owned());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PasswordResetConfig {
    pub signing_key: SecretString,
    pub ttl_seconds: u64,
}

impl Default for PasswordResetConfig {
    fn default() -> Self {
        Self {
            signing_key: SecretString::new(""),
            ttl_seconds: 3600,
        }
    }
}

impl Validatable for PasswordResetConfig {
    fn validate(&self) -> ValidationResult {
        pero_validate_core::ensure(
            !self.signing_key.is_empty(),
            "password_reset.signing_key",
            "required",
            "password_reset.signing_key must not be empty",
        )?;
        pero_validate_core::min_length(
            self.signing_key.expose_secret(),
            32,
            "password_reset.signing_key",
        )?;
        pero_validate_core::ensure(
            self.signing_key.expose_secret() != "change-me-reset-key-32bytes!!",
            "password_reset.signing_key",
            "weak_default",
            "password_reset.signing_key must be changed from the default placeholder",
        )?;
        pero_validate_core::min(self.ttl_seconds, 1, "password_reset.ttl_seconds")?;
        Ok(())
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NotificationConfig {
    pub endpoint: String,
    pub bearer_token: SecretString,
}

impl Validatable for NotificationConfig {
    fn validate(&self) -> ValidationResult {
        if !self.endpoint.is_empty() {
            pero_validate_core::ensure(
                pero_utils::redirect::validate_provider_endpoint_uri(&self.endpoint).is_ok(),
                "notification.endpoint",
                "invalid",
                "Notification gateway must use a public HTTPS endpoint",
            )?;
            pero_validate_core::not_blank(
                self.bearer_token.expose_secret(),
                "notification.bearer_token",
            )?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub log: LogConfig,
    pub database: UserCenterDatabaseConfig,
    pub redis: RedisConfig,
    #[serde(default)]
    pub sso: SsoConfig,
    #[serde(default)]
    pub oidc: OidcConfig,
    #[serde(default)]
    pub oauth2: OAuth2Config,
    #[serde(default)]
    pub password: PasswordConfig,
    #[serde(default)]
    pub password_reset: PasswordResetConfig,
    #[serde(default)]
    pub i18n: I18nConfig,
    #[serde(default)]
    pub askama: AskamaConfig,
    #[serde(default)]
    pub http_config: HttpClientConfig,
    #[serde(default)]
    pub notification: NotificationConfig,
}

impl ParseConfigurable for AppConfig {
    fn env_list_parse_keys() -> &'static [&'static str] {
        &[]
    }
}

impl Validatable for AppConfig {
    fn validate(&self) -> ValidationResult {
        self.server.validate()?;
        self.log.validate()?;
        self.database.validate()?;
        pero_validate_core::not_blank(
            self.database.extras.encrypt_key.expose_secret(),
            "database.extras.encrypt_key",
        )?;
        pero_validate_core::min_length(
            self.database.extras.encrypt_key.expose_secret(),
            1,
            "database.extras.encrypt_key",
        )?;
        self.redis.validate()?;
        self.sso.validate()?;
        self.oidc.validate()?;
        self.oauth2.validate()?;
        self.password.validate()?;
        self.password_reset.validate()?;
        self.i18n.validate()?;
        self.askama.validate()?;
        self.http_config.validate()?;
        self.notification.validate()?;
        Ok(())
    }
}
