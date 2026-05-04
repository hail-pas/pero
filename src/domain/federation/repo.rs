use async_trait::async_trait;
use uuid::Uuid;

use crate::domain::federation::entity::{
    CreateSocialProviderRequest, SocialProvider, UpdateSocialProviderRequest,
};
use crate::shared::error::AppError;

#[async_trait]
pub trait SocialStore: Send + Sync {
    async fn create_provider(
        &self,
        req: &CreateSocialProviderRequest,
    ) -> Result<SocialProvider, AppError>;
    async fn find_provider_by_name(&self, name: &str) -> Result<Option<SocialProvider>, AppError>;
    async fn find_provider_by_id(&self, id: Uuid) -> Result<Option<SocialProvider>, AppError>;
    async fn find_enabled_provider_by_name(
        &self,
        name: &str,
    ) -> Result<Option<SocialProvider>, AppError>;
    async fn list_enabled_providers(&self) -> Result<Vec<SocialProvider>, AppError>;
    async fn list_all_providers(&self) -> Result<Vec<SocialProvider>, AppError>;
    async fn update_provider(
        &self,
        id: Uuid,
        req: &UpdateSocialProviderRequest,
    ) -> Result<SocialProvider, AppError>;
    async fn delete_provider(&self, id: Uuid) -> Result<(), AppError>;
}
