use crate::shared::error::AppError;

#[async_trait::async_trait]
pub trait KvStore: Send + Sync {
    async fn get_json<T: serde::de::DeserializeOwned>(&self, key: &str) -> Result<Option<T>, AppError>;
    async fn set_json<T: serde::Serialize + Sync>(&self, key: &str, value: &T, ttl: i64) -> Result<(), AppError>;
    async fn del(&self, key: &str) -> Result<(), AppError>;
}
