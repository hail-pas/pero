use std::{cmp, time::Duration};

use pero_validate_core::{Validatable, ValidationResult};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HttpClientConfig {
    pub timeout_secs: u64,
    pub connect_timeout_secs: u64,
    pub pool_idle_timeout_secs: u64,
    pub pool_max_idle_per_host: usize,
    pub user_agent: Option<String>,
    pub retry: RetryConfig,
    pub max_response_bytes: usize,
}

impl Default for HttpClientConfig {
    fn default() -> Self {
        Self {
            timeout_secs: 30,
            connect_timeout_secs: 5,
            pool_idle_timeout_secs: 90,
            pool_max_idle_per_host: 16,
            user_agent: None,
            retry: RetryConfig::default(),
            max_response_bytes: 2 * 1024 * 1024,
        }
    }
}

impl Validatable for HttpClientConfig {
    fn validate(&self) -> ValidationResult {
        pero_validate_core::min(self.timeout_secs, 1, "http_client.timeout_secs")?;
        pero_validate_core::min(
            self.connect_timeout_secs,
            1,
            "http_client.connect_timeout_secs",
        )?;
        pero_validate_core::min(
            self.pool_max_idle_per_host,
            1,
            "http_client.pool_max_idle_per_host",
        )?;
        pero_validate_core::min(self.max_response_bytes, 1, "http_client.max_response_bytes")?;
        self.retry.validate()?;
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RetryConfig {
    pub enabled: bool,
    pub max_retries: usize,
    pub base_delay_millis: u64,
    pub max_delay_millis: u64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_retries: 3,
            base_delay_millis: 100,
            max_delay_millis: 2000,
        }
    }
}

impl RetryConfig {
    pub fn delay_for_attempt(&self, attempt: usize) -> Duration {
        let base = Duration::from_millis(self.base_delay_millis);
        let cap = Duration::from_millis(self.max_delay_millis);
        let exp = 2u32.checked_pow(attempt.min(32) as u32).unwrap_or(u32::MAX);
        cmp::min(base.saturating_mul(exp), cap)
    }
}

impl Validatable for RetryConfig {
    fn validate(&self) -> ValidationResult {
        if self.enabled {
            pero_validate_core::min(self.max_retries, 1, "http_client.retry.max_retries")?;
            pero_validate_core::ensure(
                self.base_delay_millis <= self.max_delay_millis,
                "http_client.retry.base_delay_millis",
                "range",
                "http_client.retry.base_delay_millis cannot be greater than max_delay_millis",
            )?;
        }

        Ok(())
    }
}
