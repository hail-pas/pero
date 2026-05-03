use async_trait::async_trait;

use crate::domain::sso::models::SsoSession;
use crate::shared::error::AppError;

#[async_trait]
pub trait SsoSessionStore: Send + Sync {
    async fn create(&self, session: &SsoSession, ttl_seconds: i64) -> Result<String, AppError>;
    async fn get(&self, session_id: &str) -> Result<Option<SsoSession>, AppError>;
    async fn update(
        &self,
        session_id: &str,
        session: &SsoSession,
        ttl_seconds: i64,
    ) -> Result<(), AppError>;
    async fn delete(&self, session_id: &str) -> Result<(), AppError>;
}
