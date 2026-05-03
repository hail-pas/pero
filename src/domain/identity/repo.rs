use async_trait::async_trait;
use uuid::Uuid;

use crate::domain::identity::models::{Identity, UpdateMeRequest, UpdateUserRequest, User};
use crate::domain::identity::session::IdentitySession;
use crate::domain::identity::store::{AttributeItem, UserAttribute};
use crate::shared::error::AppError;

#[async_trait]
pub trait UserStore: Send + Sync {
    async fn find_by_id(&self, id: Uuid) -> Result<Option<User>, AppError>;
    async fn find_by_username(&self, username: &str) -> Result<Option<User>, AppError>;
    async fn find_by_email(&self, email: &str) -> Result<Option<User>, AppError>;
    async fn find_by_phone(&self, phone: &str) -> Result<Option<User>, AppError>;
    async fn list(&self, page: i64, page_size: i64) -> Result<(Vec<User>, i64), AppError>;
    async fn update_admin(
        &self,
        id: Uuid,
        req: &UpdateUserRequest,
        reset_email_verified: bool,
        reset_phone_verified: bool,
    ) -> Result<User, AppError>;
    async fn update_self(
        &self,
        id: Uuid,
        req: &UpdateMeRequest,
        reset_email_verified: bool,
        reset_phone_verified: bool,
    ) -> Result<User, AppError>;
    async fn delete(&self, id: Uuid) -> Result<(), AppError>;
    async fn set_email_verified(&self, user_id: Uuid, email: &str) -> Result<(), AppError>;
    async fn set_phone_verified(&self, user_id: Uuid, phone: &str) -> Result<(), AppError>;
    async fn check_new_user_conflicts(
        &self,
        username: &str,
        email: Option<&str>,
        phone: Option<&str>,
    ) -> Result<(), AppError>;
    async fn check_update_user_conflicts(
        &self,
        id: Uuid,
        username: Option<&str>,
        email: Option<&str>,
        phone: Option<&str>,
    ) -> Result<(), AppError>;
    async fn create_with_password(
        &self,
        username: &str,
        email: Option<&str>,
        phone: Option<&str>,
        nickname: Option<&str>,
        password_hash: &str,
    ) -> Result<User, AppError>;
    async fn find_by_social_identity(
        &self,
        provider: &str,
        provider_uid: &str,
    ) -> Result<Option<User>, AppError>;
    async fn link_social_identity(
        &self,
        user_id: Uuid,
        provider: &str,
        provider_uid: &str,
    ) -> Result<(), AppError>;
    async fn set_email_verified_flag(&self, user_id: Uuid) -> Result<(), AppError>;
    async fn create_social_user(
        &self,
        username: &str,
        email: Option<&str>,
        nickname: Option<&str>,
        provider: &str,
        provider_uid: &str,
        email_verified: bool,
    ) -> Result<User, AppError>;
    async fn resolve_unique_username(&self, base: &str) -> Result<String, AppError>;
}

#[async_trait]
pub trait IdentityStore: Send + Sync {
    async fn create_password(&self, user_id: Uuid, password_hash: &str)
        -> Result<Identity, AppError>;
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

#[async_trait]
pub trait UserAttributeStore: Send + Sync {
    async fn list_by_user(&self, user_id: Uuid) -> Result<Vec<UserAttribute>, AppError>;
    async fn upsert(&self, user_id: Uuid, items: &[AttributeItem]) -> Result<(), AppError>;
    async fn delete_by_user(&self, user_id: Uuid, key: &str) -> Result<(), AppError>;
}

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
