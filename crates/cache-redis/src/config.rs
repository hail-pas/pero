use pero_types::RedisUrl;
use pero_validate_core::{Validatable, ValidationResult};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedisConfig {
    pub url: RedisUrl,
    #[serde(default = "default_redis_pool_size")]
    pub pool_size: usize,
    #[serde(default = "default_redis_connect_timeout_secs")]
    pub connect_timeout_secs: u64,
    #[serde(default = "default_redis_command_timeout_secs")]
    pub command_timeout_secs: u64,
}

impl Validatable for RedisConfig {
    fn validate(&self) -> ValidationResult {
        pero_validate_core::min(self.pool_size, 1, "redis.pool_size")?;
        pero_validate_core::min(self.connect_timeout_secs, 1, "redis.connect_timeout_secs")?;
        pero_validate_core::min(self.command_timeout_secs, 1, "redis.command_timeout_secs")?;

        Ok(())
    }
}

fn default_redis_pool_size() -> usize {
    16
}

fn default_redis_connect_timeout_secs() -> u64 {
    5
}

fn default_redis_command_timeout_secs() -> u64 {
    3
}
