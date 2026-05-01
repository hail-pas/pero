use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub redis: RedisConfig,
    pub jwt: JwtConfig,
    pub log: LogConfig,
    pub abac: AbacConfig,
    pub oidc: OidcConfig,
    pub oauth2: OAuth2Config,
    #[serde(default)]
    pub sso: SsoConfig,
    #[serde(default)]
    pub docs: DocsConfig,
    #[serde(default)]
    pub cors: CorsConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct OidcConfig {
    pub issuer: String,
    pub private_key_path: String,
    pub public_key_path: String,
    pub key_id: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct OAuth2Config {
    pub auth_code_ttl_minutes: i64,
    pub access_token_ttl_minutes: i64,
    pub refresh_token_ttl_days: i64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct SsoConfig {
    #[serde(default = "default_sso_session_ttl")]
    pub session_ttl_seconds: i64,
    #[serde(default = "default_sso_cookie_secure")]
    pub cookie_secure: bool,
    #[serde(default = "default_sso_cookie_same_site")]
    pub cookie_same_site: String,
    #[serde(default = "default_sso_default_locale")]
    pub default_locale: String,
    #[serde(default = "default_sso_password_reset_ttl")]
    pub password_reset_ttl_seconds: i64,
    #[serde(default = "default_sso_email_verify_ttl")]
    pub email_verify_ttl_seconds: i64,
    #[serde(default = "default_sso_phone_verify_ttl")]
    pub phone_verify_ttl_seconds: i64,
}

fn default_sso_session_ttl() -> i64 {
    600
}
fn default_sso_cookie_secure() -> bool {
    true
}
fn default_sso_cookie_same_site() -> String {
    "Lax".into()
}
fn default_sso_default_locale() -> String {
    "en".into()
}
fn default_sso_password_reset_ttl() -> i64 {
    1800
}
fn default_sso_email_verify_ttl() -> i64 {
    86400
}
fn default_sso_phone_verify_ttl() -> i64 {
    1800
}

impl Default for SsoConfig {
    fn default() -> Self {
        Self {
            session_ttl_seconds: 600,
            cookie_secure: true,
            cookie_same_site: "Lax".into(),
            default_locale: "en".into(),
            password_reset_ttl_seconds: 1800,
            email_verify_ttl_seconds: 86400,
            phone_verify_ttl_seconds: 1800,
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub request_body_limit_bytes: usize,
    #[serde(default = "default_rate_limit_rpm")]
    pub rate_limit_rpm: u32,
    #[serde(default = "default_cleanup_interval_secs")]
    pub cleanup_interval_secs: u64,
}

fn default_rate_limit_rpm() -> u32 {
    60
}

fn default_cleanup_interval_secs() -> u64 {
    3600
}

#[derive(Debug, Deserialize, Clone)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
    pub min_connections: u32,
}

#[derive(Debug, Deserialize, Clone)]
pub struct RedisConfig {
    pub url: String,
    pub pool_size: usize,
}

#[derive(Debug, Deserialize, Clone)]
pub struct JwtConfig {
    pub access_ttl_minutes: i64,
    pub refresh_ttl_days: i64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct LogConfig {
    pub level: String,
    pub dir: String,
    pub rotation: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AbacConfig {
    pub default_action: String,
    pub policy_cache_ttl_seconds: i64,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct DocsConfig {
    #[serde(default)]
    pub servers: Vec<DocsServer>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DocsServer {
    pub url: String,
    pub description: String,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct CorsConfig {
    #[serde(default)]
    pub allow_origins: Vec<String>,
    #[serde(default)]
    pub allow_methods: Vec<String>,
    #[serde(default)]
    pub allow_headers: Vec<String>,
}

impl AppConfig {
    pub fn load() -> Result<Self, config::ConfigError> {
        let run_mode = std::env::var("RUN_MODE").unwrap_or_else(|_| "development".into());

        let cfg = config::Config::builder()
            .add_source(config::File::with_name("config/default"))
            .add_source(config::File::with_name(&format!("config/{run_mode}")).required(false))
            .add_source(
                config::Environment::with_prefix("PERO")
                    .separator("__")
                    .try_parsing(true),
            )
            .build()?;

        cfg.try_deserialize()
    }
}
