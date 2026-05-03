use crate::shared::error::AppError;

#[async_trait::async_trait]
pub trait KvStore: Send + Sync {
    async fn get_raw(&self, key: &str) -> Result<Option<serde_json::Value>, AppError>;
    async fn set_raw(&self, key: &str, value: serde_json::Value, ttl: i64) -> Result<(), AppError>;
    async fn del(&self, key: &str) -> Result<(), AppError>;
}

#[async_trait::async_trait]
pub trait KvStoreExt: KvStore {
    async fn get_json<T>(&self, key: &str) -> Result<Option<T>, AppError>
    where
        T: serde::de::DeserializeOwned + Send,
    {
        match self.get_raw(key).await? {
            Some(value) => serde_json::from_value(value).map(Some).map_err(|e| {
                AppError::Internal(format!(
                    "failed to deserialize cached value for key `{key}` as {}: {e}",
                    std::any::type_name::<T>()
                ))
            }),
            None => Ok(None),
        }
    }

    async fn set_json<T>(&self, key: &str, value: &T, ttl: i64) -> Result<(), AppError>
    where
        T: serde::Serialize + Sync,
    {
        let value = serde_json::to_value(value).map_err(|e| {
            AppError::Internal(format!(
                "failed to serialize cached value for key `{key}` as {}: {e}",
                std::any::type_name::<T>()
            ))
        })?;
        self.set_raw(key, value, ttl).await
    }
}

impl<T: KvStore + ?Sized> KvStoreExt for T {}
