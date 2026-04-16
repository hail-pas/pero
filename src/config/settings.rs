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
    pub docs: DocsConfig,
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
#[allow(dead_code)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub workers: usize,
    pub request_body_limit_bytes: usize,
    pub rate_limit_rps: u64,
    pub rate_limit_burst: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
    pub min_connections: u32,
}

#[derive(Debug, Deserialize, Clone)]
#[allow(dead_code)]
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
#[allow(dead_code)]
pub struct LogConfig {
    pub level: String,
    pub dir: String,
    pub rotation: String,
    pub max_age_days: usize,
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
