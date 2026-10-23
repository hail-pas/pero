use std::{borrow::Cow, time::Duration};

use deadpool_redis::{
    Config as DeadpoolRedisConfig, Pool, PoolConfig, Runtime, Timeouts,
    redis::{self, FromRedisValue, Value},
};
use pero_error::AppError;
use pero_validate_core::{
    Validatable, ValidationError, ValidationLocation, ValidationResult, ValidationSource,
};

use crate::{CacheKey, CacheValue, RedisConfig};

pub type CacheResult<T> = Result<T, AppError>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CacheCommandValue {
    Simple(String),
    Integer(i64),
    Bulk(Vec<u8>),
    Array(Vec<CacheCommandValue>),
    Nil,
}

impl CacheCommandValue {
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Self::Integer(value) => Some(*value),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandArg<'a>(Cow<'a, [u8]>);

impl<'a> CommandArg<'a> {
    pub fn str(value: &'a str) -> Self {
        Self(Cow::Borrowed(value.as_bytes()))
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<'a> From<i64> for CommandArg<'a> {
    fn from(value: i64) -> Self {
        Self(Cow::Owned(value.to_string().into_bytes()))
    }
}

fn redis_value_to_cache(value: Value) -> CacheCommandValue {
    match value {
        Value::Nil => CacheCommandValue::Nil,
        Value::Int(n) => CacheCommandValue::Integer(n),
        Value::SimpleString(s) => CacheCommandValue::Simple(s),
        Value::BulkString(data) => CacheCommandValue::Bulk(data),
        Value::Array(items) => {
            CacheCommandValue::Array(items.into_iter().map(redis_value_to_cache).collect())
        }
        _ => CacheCommandValue::Nil,
    }
}

fn encode_json<T: CacheValue>(value: &T, key: &CacheKey<T>) -> CacheResult<Vec<u8>> {
    serde_json::to_vec(value).map_err(|err| {
        AppError::json_internal(
            "cache_json_encode_failed",
            "Failed to serialize value for cache storage",
            err,
        )
        .with_extension("cache_key", key.to_string())
    })
}

fn decode_json<T: CacheValue>(bytes: &[u8], key: &CacheKey<T>) -> CacheResult<T> {
    serde_json::from_slice(bytes).map_err(|err| {
        AppError::json_internal(
            "cache_json_decode_failed",
            "Failed to deserialize cached JSON value",
            err,
        )
        .with_extension("cache_key", key.to_string())
    })
}

#[derive(Debug, Clone)]
pub struct RedisCacheStore {
    pool: Pool,
    connect_timeout: Duration,
    command_timeout: Duration,
}

impl RedisCacheStore {
    pub fn from_config(config: &RedisConfig) -> ValidationResult<Self> {
        config.validate()?;

        let connect_timeout = Duration::from_secs(config.connect_timeout_secs);
        let command_timeout = Duration::from_secs(config.command_timeout_secs);

        let mut redis_config = DeadpoolRedisConfig::from_url(config.url.expose_secret());

        redis_config.pool = Some(PoolConfig {
            max_size: config.pool_size,
            timeouts: Timeouts {
                wait: Some(connect_timeout),
                create: Some(connect_timeout),
                recycle: Some(connect_timeout),
            },
            queue_mode: Default::default(),
        });

        let pool = redis_config
            .create_pool(Some(Runtime::Tokio1))
            .map_err(|err| {
                ValidationError::malformed_input(
                    ValidationSource::new(ValidationLocation::Config),
                    format!("Failed to create Redis connection pool {err}"),
                )
            })?;

        Ok(Self {
            pool,
            connect_timeout,
            command_timeout,
        })
    }

    async fn get_conn(&self, operation: &str) -> CacheResult<deadpool_redis::Connection> {
        // Pool recycling can retry multiple stale connections. Bound the entire
        // acquisition, rather than allowing the timeout to restart per connection.
        tokio::time::timeout(self.connect_timeout, self.pool.get())
            .await
            .map_err(|_| {
                AppError::internal(
                    "redis_pool_timeout",
                    "Redis connection acquisition timed out",
                )
                .with_extension("redis_operation", operation.to_owned())
            })?
            .map_err(|err| {
                AppError::internal(
                    "redis_pool_get_failed",
                    "Failed to get Redis connection from pool",
                )
                .with_source(err)
                .with_extension("redis_operation", operation.to_owned())
            })
    }

    fn timeout_err(&self, operation: &str) -> AppError {
        AppError::internal("redis_command_timeout", "Redis command timed out")
            .with_extension("redis_operation", operation.to_owned())
            .with_extension("timeout_secs", self.command_timeout.as_secs().to_string())
    }

    fn redis_err(
        &self,
        err: impl std::error::Error + Send + Sync + 'static,
        operation: &str,
    ) -> AppError {
        AppError::internal("redis_command_failed", "Redis command failed")
            .with_source(err)
            .with_extension("redis_operation", operation.to_owned())
    }

    async fn query<R>(&self, cmd: redis::Cmd, operation: &str) -> CacheResult<R>
    where
        R: FromRedisValue + Send + 'static,
    {
        let mut conn = self.get_conn(operation).await?;
        tokio::time::timeout(self.command_timeout, cmd.query_async::<R>(&mut conn))
            .await
            .map_err(|_| self.timeout_err(operation))?
            .map_err(|err| self.redis_err(err, operation))
    }

    pub async fn get_bytes(&self, key: &str) -> CacheResult<Option<Vec<u8>>> {
        pero_validate_core::not_blank(key, "key")?;

        let mut cmd = redis::cmd("GET");
        cmd.arg(key);

        self.query(cmd, "GET").await
    }

    pub async fn set_bytes(
        &self,
        key: &str,
        value: &[u8],
        ttl: Option<Duration>,
    ) -> CacheResult<()> {
        pero_validate_core::not_blank(key, "key")?;

        let mut cmd = redis::cmd("SET");
        cmd.arg(key).arg(value);

        if let Some(duration) = ttl {
            cmd.arg("PX").arg(duration.as_millis() as u64);
        }

        self.query(cmd, "SET").await
    }

    pub async fn del<T: CacheValue>(&self, key: CacheKey<T>) -> CacheResult<bool> {
        let mut cmd = redis::cmd("DEL");
        cmd.arg(key.as_str());

        let deleted: u64 = self.query(cmd, "DEL").await?;
        Ok(deleted > 0)
    }

    pub async fn get<T>(&self, key: CacheKey<T>) -> CacheResult<Option<T>>
    where
        T: CacheValue,
    {
        let Some(bytes) = self.get_bytes(key.as_str()).await? else {
            return Ok(None);
        };

        Ok(Some(decode_json(&bytes, &key)?))
    }

    pub async fn take<T>(&self, key: CacheKey<T>) -> CacheResult<Option<T>>
    where
        T: CacheValue,
    {
        let mut cmd = redis::cmd("GETDEL");
        cmd.arg(key.as_str());

        let result: Option<Vec<u8>> = self.query(cmd, "GETDEL").await?;

        let Some(bytes) = result else {
            return Ok(None);
        };

        Ok(Some(decode_json(&bytes, &key)?))
    }

    pub async fn set<T>(&self, key: CacheKey<T>, value: &T) -> CacheResult<()>
    where
        T: CacheValue,
    {
        let encoded = encode_json(value, &key)?;
        self.set_bytes(key.as_str(), &encoded, key.ttl()).await
    }

    pub async fn command<'a>(
        &self,
        cmd: &'a str,
        args: &'a [CommandArg<'a>],
    ) -> CacheResult<CacheCommandValue> {
        let cmd = cmd.trim();

        if cmd.is_empty() {
            return Err(AppError::internal(
                "redis_command_empty",
                "Redis command must not be empty",
            ));
        }

        let mut command = redis::cmd(cmd);

        for arg in args {
            command.arg(arg.as_bytes());
        }

        let value: Value = self.query(command, cmd).await?;
        Ok(redis_value_to_cache(value))
    }
}
