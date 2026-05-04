use super::models::{CreatePolicyRequest, Policy, PolicyCondition, UpdatePolicyRequest};
use super::repo::{AbacCacheStore, AbacStore, PolicyFilter};
use crate::domain::user::repo::UserStore;
use crate::shared::constants::identity;
use crate::shared::error::{AppError, require_found};
use crate::shared::page::PageData;
use crate::shared::patch::FieldUpdate;
use serde::Serialize;
use std::collections::HashMap;
use utoipa::ToSchema;
use uuid::Uuid;

pub type AttachedPolicies = Vec<(Policy, Vec<PolicyCondition>)>;

#[derive(Debug, Serialize, ToSchema)]
pub struct PolicyDTO {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub effect: String,
    pub priority: i32,
    pub enabled: bool,
    pub app_id: Option<Uuid>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub conditions: Vec<PolicyCondition>,
}

impl PolicyDTO {
    pub fn from_policy_with_conditions(policy: Policy, conditions: Vec<PolicyCondition>) -> Self {
        Self {
            id: policy.id,
            name: policy.name,
            description: policy.description,
            effect: policy.effect,
            priority: policy.priority,
            enabled: policy.enabled,
            app_id: policy.app_id,
            created_at: policy.created_at,
            updated_at: policy.updated_at,
            conditions,
        }
    }

    pub fn from_attached(attached: Vec<(Policy, Vec<PolicyCondition>)>) -> Vec<Self> {
        attached
            .into_iter()
            .map(|(policy, conditions)| Self::from_policy_with_conditions(policy, conditions))
            .collect()
    }
}

#[derive(Debug, Clone, Copy)]
pub enum PolicyScope {
    Any,
    App(Uuid),
}

pub async fn build_subject_attrs(
    policies: &dyn AbacStore,
    abac_cache: &dyn AbacCacheStore,
    user_id: Uuid,
    roles: &[String],
    cache_ttl: i64,
) -> Result<HashMap<String, Vec<String>>, AppError> {
    let mut subject_attrs: HashMap<String, Vec<String>> =
        match abac_cache.get_subject_attrs(user_id).await {
            Ok(Some(cached)) => cached,
            _ => {
                let mut attrs: HashMap<String, Vec<String>> = HashMap::new();
                for (key, value) in policies.load_user_attributes(user_id).await? {
                    attrs.entry(key).or_default().push(value);
                }
                if let Err(e) = abac_cache
                    .set_subject_attrs(user_id, &attrs, cache_ttl)
                    .await
                {
                    tracing::warn!(error = %e, "failed to cache ABAC subject attrs");
                }
                attrs
            }
        };

    for role in roles {
        subject_attrs
            .entry(identity::ROLE_ATTR_KEY.to_string())
            .or_default()
            .push(role.clone());
    }

    Ok(subject_attrs)
}

pub async fn create_policy_dto(
    policies: &dyn AbacStore,
    abac_cache: &dyn AbacCacheStore,
    cache_ttl: i64,
    mut req: CreatePolicyRequest,
    forced_app_id: Option<Uuid>,
) -> Result<PolicyDTO, AppError> {
    if let Some(app_id) = forced_app_id {
        req.app_id = Some(app_id);
    }
    let (policy, conditions) = policies.create_policy(&req).await?;
    let dto = PolicyDTO::from_policy_with_conditions(policy, conditions);
    invalidate_policy_cache_best_effort(abac_cache, dto.app_id, cache_ttl).await;
    Ok(dto)
}

pub async fn list_policy_page(
    policies: &dyn AbacStore,
    scope: PolicyScope,
    page: i64,
    page_size: i64,
) -> Result<PageData<PolicyDTO>, AppError> {
    let (policies_list, total) = match scope {
        PolicyScope::Any => policies.list_policies(page, page_size).await?,
        PolicyScope::App(app_id) => {
            policies
                .list_policies_by_app(app_id, page, page_size)
                .await?
        }
    };
    let attached = policies.attach_conditions(policies_list).await?;
    Ok(PageData::new(
        PolicyDTO::from_attached(attached),
        total,
        page,
        page_size,
    ))
}

pub async fn get_policy_dto(
    policies: &dyn AbacStore,
    id: Uuid,
    scope: PolicyScope,
) -> Result<PolicyDTO, AppError> {
    let policy = load_policy_in_scope(policies, id, scope).await?;
    Ok(PolicyDTO::from_policy_with_conditions(policy, vec![]))
}

pub async fn update_policy_dto(
    policies: &dyn AbacStore,
    abac_cache: &dyn AbacCacheStore,
    cache_ttl: i64,
    id: Uuid,
    mut req: UpdatePolicyRequest,
    scope: PolicyScope,
    forced_app_id: Option<Uuid>,
) -> Result<PolicyDTO, AppError> {
    let policy = load_policy_in_scope(policies, id, scope).await?;
    if let Some(app_id) = forced_app_id {
        req.app_id = FieldUpdate::Set(app_id);
    }
    let old_app_id = policy.app_id;
    let (updated, conditions) = policies.update_policy(id, &req, &policy).await?;
    let dto = PolicyDTO::from_policy_with_conditions(updated, conditions);
    invalidate_policy_cache_best_effort(abac_cache, dto.app_id, cache_ttl).await;
    if dto.app_id != old_app_id {
        invalidate_policy_cache_best_effort(abac_cache, old_app_id, cache_ttl).await;
    }
    Ok(dto)
}

pub async fn delete_policy_in_scope(
    policies: &dyn AbacStore,
    abac_cache: &dyn AbacCacheStore,
    cache_ttl: i64,
    id: Uuid,
    scope: PolicyScope,
) -> Result<(), AppError> {
    let policy = load_policy_in_scope(policies, id, scope).await?;
    policies.delete_policy(id).await?;
    invalidate_policy_cache_best_effort(abac_cache, policy.app_id, cache_ttl).await;
    Ok(())
}

pub async fn assign_policy_to_user_in_scope(
    policies: &dyn AbacStore,
    abac_cache: &dyn AbacCacheStore,
    cache_ttl: i64,
    user_id: Uuid,
    policy_id: Uuid,
    scope: PolicyScope,
) -> Result<(), AppError> {
    let policy = load_policy_in_scope(policies, policy_id, scope).await?;
    policies.assign_policy(user_id, policy_id).await?;
    invalidate_policy_cache_best_effort(abac_cache, policy.app_id, cache_ttl).await;
    invalidate_user_cache_best_effort(abac_cache, user_id, cache_ttl).await;
    Ok(())
}

pub async fn unassign_policy_from_user_in_scope(
    policies: &dyn AbacStore,
    abac_cache: &dyn AbacCacheStore,
    cache_ttl: i64,
    user_id: Uuid,
    policy_id: Uuid,
    scope: PolicyScope,
) -> Result<(), AppError> {
    let policy = load_policy_in_scope(policies, policy_id, scope).await?;
    policies.unassign_policy(user_id, policy_id).await?;
    invalidate_policy_cache_best_effort(abac_cache, policy.app_id, cache_ttl).await;
    invalidate_user_cache_best_effort(abac_cache, user_id, cache_ttl).await;
    Ok(())
}

pub async fn list_user_policy_dtos(
    users: &dyn UserStore,
    policies: &dyn AbacStore,
    user_id: Uuid,
    scope: PolicyScope,
) -> Result<Vec<PolicyDTO>, AppError> {
    users
        .find_by_id(user_id)
        .await?
        .ok_or_else(|| AppError::NotFound("user".into()))?;

    let app_id = match scope {
        PolicyScope::Any => None,
        PolicyScope::App(app_id) => Some(app_id),
    };
    let policies_list = policies
        .select_policies(PolicyFilter {
            user_id: Some(user_id),
            app_id,
            enabled_only: false,
        })
        .await?;
    let attached = policies.attach_conditions(policies_list).await?;
    Ok(PolicyDTO::from_attached(attached))
}

pub async fn load_user_policies(
    policies: &dyn AbacStore,
    abac_cache: &dyn AbacCacheStore,
    user_id: Uuid,
    app_id: Option<Uuid>,
    use_cache: bool,
    cache_ttl: i64,
) -> Result<AttachedPolicies, AppError> {
    let load = || async {
        let filter = PolicyFilter {
            user_id: Some(user_id),
            app_id,
            enabled_only: true,
        };
        let policies_list = policies.select_policies(filter).await?;
        policies.attach_conditions(policies_list).await
    };

    if !use_cache {
        return load().await;
    }

    match abac_cache.get_policies(user_id, app_id).await {
        Ok(Some(cached)) => Ok(cached),
        _ => {
            let result = load().await?;
            if let Err(e) = abac_cache
                .set_policies(user_id, app_id, &result, cache_ttl)
                .await
            {
                tracing::warn!(error = %e, "failed to cache ABAC policies");
            }
            Ok(result)
        }
    }
}

pub async fn invalidate_policy_cache_best_effort(
    abac_cache: &dyn AbacCacheStore,
    app_id: Option<Uuid>,
    cache_ttl: i64,
) {
    if let Err(e) = abac_cache.bump_app_policy_version(app_id, cache_ttl).await {
        tracing::warn!(error = %e, app_id = ?app_id, "failed to invalidate ABAC policy cache");
    }
}

pub async fn invalidate_user_cache_best_effort(
    abac_cache: &dyn AbacCacheStore,
    user_id: Uuid,
    cache_ttl: i64,
) {
    if let Err(e) = abac_cache.bump_user_version(user_id, cache_ttl).await {
        tracing::warn!(error = %e, %user_id, "failed to invalidate ABAC user cache");
    }
}

async fn load_policy_in_scope(
    policies: &dyn AbacStore,
    id: Uuid,
    scope: PolicyScope,
) -> Result<Policy, AppError> {
    let policy = require_found(policies.find_policy_by_id(id).await?, "policy")?;
    ensure_policy_scope(&policy, scope)?;
    Ok(policy)
}

fn ensure_policy_scope(policy: &Policy, scope: PolicyScope) -> Result<(), AppError> {
    match scope {
        PolicyScope::Any => Ok(()),
        PolicyScope::App(app_id) if policy.app_id == Some(app_id) => Ok(()),
        PolicyScope::App(_) => Err(AppError::NotFound("policy".into())),
    }
}
