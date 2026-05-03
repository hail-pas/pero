use crate::infra::cache;
use crate::shared::error::AppError;
use crate::shared::kv::KvStore;

pub struct RedisKvStore {
    pool: cache::Pool,
}

impl RedisKvStore {
    pub fn new(pool: cache::Pool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl KvStore for RedisKvStore {
    async fn get_json<T: serde::de::DeserializeOwned>(&self, key: &str) -> Result<Option<T>, AppError> {
        cache::get_json(&self.pool, key).await
    }

    async fn set_json<T: serde::Serialize + Sync>(&self, key: &str, value: &T, ttl: i64) -> Result<(), AppError> {
        cache::set_json(&self.pool, key, value, ttl).await
    }

    async fn del(&self, key: &str) -> Result<(), AppError> {
        cache::del(&self.pool, key).await
    }
}
