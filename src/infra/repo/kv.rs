use crate::infra::cache;
use crate::shared::error::AppError;

pub struct RedisKvStore {
    pool: cache::Pool,
}

impl RedisKvStore {
    pub fn new(pool: cache::Pool) -> Self {
        Self { pool }
    }

    pub fn pool(&self) -> &cache::Pool {
        &self.pool
    }

    pub async fn get_json<T: serde::de::DeserializeOwned>(&self, key: &str) -> Result<Option<T>, AppError> {
        cache::get_json(&self.pool, key).await
    }

    pub async fn set_json<T: serde::Serialize + Sync>(&self, key: &str, value: &T, ttl: i64) -> Result<(), AppError> {
        cache::set_json(&self.pool, key, value, ttl).await
    }

    pub async fn del(&self, key: &str) -> Result<(), AppError> {
        cache::del(&self.pool, key).await
    }
}
