use async_trait::async_trait;
use uuid::Uuid;

use crate::domain::auth::session::IdentitySession;
use crate::shared::error::AppError;

#[async_trait]
pub trait SessionStore: Send + Sync {
    async fn create(
        &self,
        user_id: Uuid,
        ttl_days: i64,
        device: &str,
        location: &str,
    ) -> Result<(IdentitySession, String), AppError>;
    async fn get(&self, session_id: &str) -> Result<Option<IdentitySession>, AppError>;
    async fn rotate(
        &self,
        session_id: &str,
        old_hash: &str,
        new_token: &str,
        ttl_days: i64,
    ) -> Result<bool, AppError>;
    async fn revoke(&self, session_id: &str) -> Result<(), AppError>;
    async fn revoke_all_for_user(&self, user_id: Uuid) -> Result<(), AppError>;
    async fn list_user_session_ids(&self, user_id: Uuid) -> Result<Vec<String>, AppError>;
    async fn verify(&self, session_id: &str, user_id: Uuid) -> Result<IdentitySession, AppError>;
}
