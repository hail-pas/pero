use pero_cache_redis::RedisConfig;
use pero_config::ParseConfigurable;
use pero_config::blocks::{FrontendConfig, LogConfig, ServerConfig};
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
}

impl Default for OAuth2Config {
    fn default() -> Self {
        Self {
            upstream_jwks_cache_ttl_seconds: 0,
            auth_code_ttl_seconds: 600,
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
    pub smtp: Option<SmtpConfig>,
    pub sms: Option<SmsConfig>,
    pub endpoint: String,
    pub bearer_token: SecretString,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SmtpConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: SecretString,
    pub from: String,
    /// "tls" (implicit TLS) or "starttls". Plaintext is intentionally unsupported.
    pub security: String,
}
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SmsConfig {
    pub account_sid: String,
    pub auth_token: SecretString,
    pub from: String,
}
impl NotificationConfig {
    pub fn available(&self, channel: &str) -> bool {
        match channel {
            "email" if self.smtp.is_some() => {
                self.smtp.as_ref().is_some_and(|c| c.transport().is_ok())
            }
            "phone" if self.sms.is_some() => self.sms.as_ref().is_some_and(|c| {
                c.account_sid.starts_with("AC")
                    && c.account_sid.len() == 34
                    && c.account_sid[2..].bytes().all(|b| b.is_ascii_hexdigit())
                    && !c.auth_token.is_empty()
                    && !c.from.is_empty()
            }),
            "email" | "phone" => !self.endpoint.is_empty() && !self.bearer_token.is_empty(),
            _ => false,
        }
    }
}
impl SmtpConfig {
    pub fn transport(
        &self,
    ) -> Result<lettre::AsyncSmtpTransport<lettre::Tokio1Executor>, &'static str> {
        use lettre::{
            AsyncSmtpTransport, Tokio1Executor, transport::smtp::authentication::Credentials,
        };
        if self.host.is_empty()
            || self.port == 0
            || self.from.parse::<lettre::message::Mailbox>().is_err()
        {
            return Err("smtp_not_configured");
        }
        let builder = match self.security.as_str() {
            "tls" => AsyncSmtpTransport::<Tokio1Executor>::relay(&self.host),
            "starttls" => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&self.host),
            _ => return Err("smtp_invalid_security"),
        }
        .map_err(|_| "smtp_invalid_configuration")?;
        let mut builder = builder
            .port(self.port)
            .timeout(Some(std::time::Duration::from_secs(30)));
        if !self.username.is_empty() {
            if self.password.is_empty() {
                return Err("smtp_missing_password");
            }
            builder = builder.credentials(Credentials::new(
                self.username.clone(),
                self.password.expose_secret().to_owned(),
            ));
        }
        Ok(builder.build())
    }
}
impl Validatable for NotificationConfig {
    fn validate(&self) -> ValidationResult {
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
    pub frontend: FrontendConfig,
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
        self.http_config.validate()?;
        self.notification.validate()?;
        Ok(())
    }
}

#[cfg(test)]
mod notification_tests {
    use super::*;
    #[test]
    fn optional_notification_configuration_is_checked_at_send_time() {
        let config = NotificationConfig::default();
        assert!(config.validate().is_ok());
        assert!(!config.available("email"));
        assert!(!config.available("phone"));
        let mut config = config;
        config.smtp = Some(SmtpConfig::default());
        assert!(config.validate().is_ok());
        assert!(!config.available("email"));
        config.smtp = Some(SmtpConfig {
            host: "smtp.example.test".into(),
            port: 587,
            from: "Pero <notify@example.test>".into(),
            security: "starttls".into(),
            ..Default::default()
        });
        assert!(config.available("email"));
        assert!(!config.available("phone"));
    }
}
