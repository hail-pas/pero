use ipnetwork::IpNetwork;
use pero_validate_core::{Validatable, ValidationResult};
use serde::Deserialize;
use url::Url;

pub const COMMON_ENV_LIST_PARSE_KEYS: &[&str] = &[
    "server.docs_servers",
    "server.trusted_proxies",
    "server.cors.allow_origins",
    "server.cors.allow_methods",
    "server.cors.allow_headers",
    "server.cors.expose_headers",
];

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub request_body_limit_bytes: usize,
    pub graceful_shutdown_timeout_secs: u64,
    pub cleanup_interval_secs: u64,
    pub docs_servers: Vec<DocsServer>,
    pub trusted_proxies: Vec<IpNetwork>,
    pub client_ip_header: ClientIpHeader,
    pub cors: CorsConfig,
}

impl ServerConfig {
    pub fn unknown_ip_placeholder() -> &'static str {
        "__unknown_ip__"
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "0.0.0.0".to_owned(),
            port: 8080,
            request_body_limit_bytes: 10 * 1024 * 1024,
            graceful_shutdown_timeout_secs: 30,
            cleanup_interval_secs: 3600,
            docs_servers: Vec::new(),
            trusted_proxies: Vec::new(),
            client_ip_header: ClientIpHeader::default(),
            cors: CorsConfig::default(),
        }
    }
}

/// Only trust the header that the configured proxy overwrites or appends.
#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientIpHeader {
    #[default]
    XForwardedFor,
    Forwarded,
    XRealIp,
}

impl Validatable for ServerConfig {
    fn validate(&self) -> ValidationResult {
        pero_validate_core::not_blank(&self.host, "server.host")?;
        pero_validate_core::min(self.port, 1, "server.port")?;
        pero_validate_core::min(
            self.request_body_limit_bytes,
            1,
            "server.request_body_limit_bytes",
        )?;
        pero_validate_core::min(
            self.graceful_shutdown_timeout_secs,
            1,
            "server.graceful_shutdown_timeout_secs",
        )?;
        pero_validate_core::min(
            self.cleanup_interval_secs,
            1,
            "server.cleanup_interval_secs",
        )?;

        for item in &self.docs_servers {
            pero_validate_core::not_blank(&item.description, "server.docs_servers[].description")?;
        }

        self.cors.validate()?;
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CorsConfig {
    pub allow_origins: Vec<String>,
    pub allow_methods: Vec<HttpMethod>,
    pub allow_headers: Vec<String>,
    pub allow_credentials: bool,
    pub expose_headers: Vec<String>,
    pub max_age_secs: Option<u64>,
}

impl Default for CorsConfig {
    fn default() -> Self {
        Self {
            allow_origins: Vec::new(),
            allow_methods: vec![
                HttpMethod::Get,
                HttpMethod::Post,
                HttpMethod::Put,
                HttpMethod::Patch,
                HttpMethod::Delete,
                HttpMethod::Options,
            ],
            allow_headers: vec![
                "authorization".to_owned(),
                "content-type".to_owned(),
                "accept-language".to_owned(),
                "x-request-id".to_owned(),
            ],
            allow_credentials: false,
            expose_headers: vec!["x-request-id".to_owned(), "x-process-time".to_owned()],
            max_age_secs: Some(3600),
        }
    }
}

impl Validatable for CorsConfig {
    fn validate(&self) -> ValidationResult {
        if self.allow_credentials {
            pero_validate_core::ensure(
                !self.allow_origins.iter().any(|origin| origin == "*"),
                "server.cors.allow_origins",
                "invalid",
                "server.cors.allow_credentials=true cannot be used with wildcard origin `*`",
            )?;
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Patch,
    Delete,
    Options,
    Head,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocsServer {
    pub url: Url,
    pub description: String,
}
