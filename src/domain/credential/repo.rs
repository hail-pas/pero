use async_trait::async_trait;
use uuid::Uuid;

use crate::domain::credential::entity::Identity;
use crate::shared::error::AppError;

#[async_trait]
pub trait IdentityStore: Send + Sync {
    async fn create_password(
        &self,
        user_id: Uuid,
        password_hash: &str,
    ) -> Result<Identity, AppError>;
    async fn create_social(
        &self,
        user_id: Uuid,
        provider: &str,
        provider_uid: &str,
    ) -> Result<Identity, AppError>;
    async fn find_by_user_and_provider(
        &self,
        user_id: Uuid,
        provider: &str,
    ) -> Result<Option<Identity>, AppError>;
    async fn find_by_provider(
        &self,
        provider: &str,
        provider_uid: &str,
    ) -> Result<Option<Identity>, AppError>;
    async fn list_by_user(&self, user_id: Uuid) -> Result<Vec<Identity>, AppError>;
    async fn delete(&self, user_id: Uuid, provider: &str) -> Result<(), AppError>;
    async fn count_by_user(&self, user_id: Uuid) -> Result<i64, AppError>;
    async fn update_credential(
        &self,
        user_id: Uuid,
        provider: &str,
        credential: &str,
    ) -> Result<(), AppError>;
}
