use async_trait::async_trait;
use uuid::Uuid;

use crate::domain::app::models::{App, CreateAppRequest, UpdateAppRequest};
use crate::shared::error::AppError;

#[async_trait]
pub trait AppStore: Send + Sync {
    async fn create(&self, req: &CreateAppRequest) -> Result<App, AppError>;
    async fn find_by_id(&self, id: Uuid) -> Result<Option<App>, AppError>;
    async fn find_by_code(&self, code: &str) -> Result<Option<App>, AppError>;
    async fn list(&self, page: i64, page_size: i64) -> Result<(Vec<App>, i64), AppError>;
    async fn update(&self, id: Uuid, req: &UpdateAppRequest) -> Result<App, AppError>;
    async fn delete(&self, id: Uuid) -> Result<(), AppError>;
}
