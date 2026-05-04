use async_trait::async_trait;
use std::collections::HashMap;
use uuid::Uuid;

use crate::domain::abac::models::{
    CreatePolicyRequest, Policy, PolicyCondition, UpdatePolicyRequest,
};
use crate::domain::abac::service::AttachedPolicies;
use crate::shared::error::AppError;

#[derive(Debug, Clone, Copy)]
pub struct PolicyFilter {
    pub user_id: Option<Uuid>,
    pub app_id: Option<Uuid>,
    pub enabled_only: bool,
}

#[async_trait]
pub trait AbacStore: Send + Sync {
    async fn create_policy(
        &self,
        req: &CreatePolicyRequest,
    ) -> Result<(Policy, Vec<PolicyCondition>), AppError>;
    async fn find_policy_by_id(&self, id: Uuid) -> Result<Option<Policy>, AppError>;
    async fn list_policies(
        &self,
        page: i64,
        page_size: i64,
    ) -> Result<(Vec<Policy>, i64), AppError>;
    async fn list_policies_by_app(
        &self,
        app_id: Uuid,
        page: i64,
        page_size: i64,
    ) -> Result<(Vec<Policy>, i64), AppError>;
    async fn update_policy(
        &self,
        id: Uuid,
        req: &UpdatePolicyRequest,
        policy: &Policy,
    ) -> Result<(Policy, Vec<PolicyCondition>), AppError>;
    async fn delete_policy(&self, id: Uuid) -> Result<(), AppError>;
    async fn select_policies(&self, filter: PolicyFilter) -> Result<Vec<Policy>, AppError>;
    async fn attach_conditions(
        &self,
        policies: Vec<Policy>,
    ) -> Result<Vec<(Policy, Vec<PolicyCondition>)>, AppError>;
    async fn load_user_attributes(&self, user_id: Uuid) -> Result<Vec<(String, String)>, AppError>;
    async fn assign_policy(&self, user_id: Uuid, policy_id: Uuid) -> Result<(), AppError>;
    async fn unassign_policy(&self, user_id: Uuid, policy_id: Uuid) -> Result<(), AppError>;
}

#[async_trait]
pub trait AbacCacheStore: Send + Sync {
    async fn get_subject_attrs(
        &self,
        user_id: Uuid,
    ) -> Result<Option<HashMap<String, Vec<String>>>, AppError>;
    async fn set_subject_attrs(
        &self,
        user_id: Uuid,
        attrs: &HashMap<String, Vec<String>>,
        ttl: i64,
    ) -> Result<(), AppError>;
    async fn get_policies(
        &self,
        user_id: Uuid,
        app_id: Option<Uuid>,
    ) -> Result<Option<AttachedPolicies>, AppError>;
    async fn set_policies(
        &self,
        user_id: Uuid,
        app_id: Option<Uuid>,
        policies: &AttachedPolicies,
        ttl: i64,
    ) -> Result<(), AppError>;
    async fn bump_policy_version(&self, app_id: Option<Uuid>, ttl: i64) -> Result<(), AppError>;
    async fn bump_user_version(&self, user_id: Uuid, ttl: i64) -> Result<(), AppError>;
}
