use std::sync::RwLock;

use crate::{CacheKey, CacheResult, CacheValue, CommandArg, RedisCacheStore};
use pero_error::AppError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RateLimitOutcome {
    Allowed { current: u64 },
    Denied { current: u64, max: u64 },
}

#[derive(Debug)]
pub enum RateLimitError {
    Denied { current: u64, max: u64 },
    Redis(pero_error::AppError),
}

impl std::fmt::Display for RateLimitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Denied { current, max } => write!(f, "rate limited ({current}/{max})"),
            Self::Redis(e) => write!(f, "redis error: {e}"),
        }
    }
}

pub async fn check_rate_limit<T: CacheValue>(
    store: &RedisCacheStore,
    key: &CacheKey<T>,
    max: u64,
) -> Result<u64, RateLimitError> {
    match rate_limit_check(store, key, max).await {
        Ok(RateLimitOutcome::Allowed { current }) => Ok(current),
        Ok(RateLimitOutcome::Denied { current, max }) => {
            Err(RateLimitError::Denied { current, max })
        }
        Err(e) => {
            tracing::error!(error = %e, "rate_limit_check redis error");
            Err(RateLimitError::Redis(e))
        }
    }
}

pub async fn enforce_rate_limit<T: CacheValue>(
    store: &RedisCacheStore,
    key: &CacheKey<T>,
    max: u64,
) -> Result<(), RateLimitError> {
    check_rate_limit(store, key, max).await.map(|_| ())
}

const INCR_SCRIPT: &str = r#"
local count = redis.call("INCR", KEYS[1])
if count == 1 then
    redis.call("EXPIRE", KEYS[1], ARGV[1])
end
return count
"#;

static SCRIPT_SHA: RwLock<Option<String>> = RwLock::new(None);

pub async fn rate_limit_check<T: CacheValue>(
    store: &RedisCacheStore,
    key: &CacheKey<T>,
    max: u64,
) -> CacheResult<RateLimitOutcome> {
    let ttl_secs = key.ttl().map(|d| d.as_secs()).unwrap_or(60);
    let count = eval_incr(store, key.as_str(), ttl_secs).await?;
    if count <= max {
        Ok(RateLimitOutcome::Allowed { current: count })
    } else {
        Ok(RateLimitOutcome::Denied {
            current: count,
            max,
        })
    }
}

async fn eval_incr(store: &RedisCacheStore, key: &str, ttl_secs: u64) -> CacheResult<u64> {
    let sha = SCRIPT_SHA.read().unwrap().clone();

    if let Some(ref sha) = sha {
        let result = store
            .command(
                "EVALSHA",
                &[
                    CommandArg::str(sha),
                    CommandArg::from(1i64),
                    CommandArg::str(key),
                    CommandArg::from(ttl_secs as i64),
                ],
            )
            .await;
        if let Ok(result) = result {
            return Ok(result.as_i64().unwrap_or(0) as u64);
        }
    }

    let load_result = store
        .command(
            "SCRIPT",
            &[CommandArg::str("LOAD"), CommandArg::str(INCR_SCRIPT)],
        )
        .await?;

    let new_sha = load_result
        .as_str()
        .ok_or_else(|| {
            AppError::internal(
                "rate_limit_script_load_failed",
                "Failed to load rate limit Lua script",
            )
        })?
        .to_owned();

    {
        let mut guard = SCRIPT_SHA.write().unwrap();
        *guard = Some(new_sha.clone());
    }

    let result = store
        .command(
            "EVALSHA",
            &[
                CommandArg::str(&new_sha),
                CommandArg::from(1i64),
                CommandArg::str(key),
                CommandArg::from(ttl_secs as i64),
            ],
        )
        .await?;

    Ok(result.as_i64().unwrap_or(0) as u64)
}
