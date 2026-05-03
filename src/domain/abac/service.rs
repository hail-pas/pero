use super::cache::AbacCache;
use super::models::{CreatePolicyRequest, Policy, PolicyCondition, UpdatePolicyRequest};
use super::store::{PolicyConditionRepo, PolicyFilter, PolicyRepo, UserPolicyRepo};
use crate::api::response::PageData;
use crate::domain::identity::store::UserRepo;
use crate::shared::constants::identity;
use crate::shared::error::{AppError, require_found};
use crate::shared::patch::Patch;
use crate::shared::state::AppState;
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
    state: &AppState,
    user_id: Uuid,
    roles: &[String],
) -> Result<HashMap<String, Vec<String>>, AppError> {
    let ttl = state.config.abac.policy_cache_ttl_seconds;

    let mut subject_attrs: HashMap<String, Vec<String>> =
        match AbacCache::get_subject_attrs::<HashMap<String, Vec<String>>>(&state.cache, user_id)
            .await
        {
            Ok(Some(cached)) => cached,
            _ => {
                let mut attrs: HashMap<String, Vec<String>> = HashMap::new();
                for (key, value) in PolicyRepo::load_user_attributes(&state.db, user_id).await? {
                    attrs.entry(key).or_default().push(value);
                }
                if let Err(e) =
                    AbacCache::set_subject_attrs(&state.cache, user_id, &attrs, ttl).await
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
    state: &AppState,
    mut req: CreatePolicyRequest,
    forced_app_id: Option<Uuid>,
) -> Result<PolicyDTO, AppError> {
    if let Some(app_id) = forced_app_id {
        req.app_id = Some(app_id);
    }
    let (policy, conditions) = PolicyRepo::create(&state.db, &req).await?;
    let dto = PolicyDTO::from_policy_with_conditions(policy, conditions);
    invalidate_policy_cache_best_effort(state, dto.app_id).await;
    Ok(dto)
}

pub async fn list_policy_page(
    state: &AppState,
    scope: PolicyScope,
    page: i64,
    page_size: i64,
) -> Result<PageData<PolicyDTO>, AppError> {
    let (policies, total) = match scope {
        PolicyScope::Any => PolicyRepo::list(&state.db, page, page_size).await?,
        PolicyScope::App(app_id) => {
            PolicyRepo::list_by_app(&state.db, app_id, page, page_size).await?
        }
    };
    let attached = PolicyRepo::attach_conditions(&state.db, policies).await?;
    Ok(PageData::new(
        PolicyDTO::from_attached(attached),
        total,
        page,
        page_size,
    ))
}

pub async fn get_policy_dto(
    state: &AppState,
    id: Uuid,
    scope: PolicyScope,
) -> Result<PolicyDTO, AppError> {
    let policy = load_policy_in_scope(state, id, scope).await?;
    let conditions = PolicyConditionRepo::get_for_policy(&state.db, policy.id).await?;
    Ok(PolicyDTO::from_policy_with_conditions(policy, conditions))
}

pub async fn update_policy_dto(
    state: &AppState,
    id: Uuid,
    mut req: UpdatePolicyRequest,
    scope: PolicyScope,
    forced_app_id: Option<Uuid>,
) -> Result<PolicyDTO, AppError> {
    let policy = load_policy_in_scope(state, id, scope).await?;
    if let Some(app_id) = forced_app_id {
        req.app_id = Patch::Set(app_id);
    }
    let old_app_id = policy.app_id;
    let (updated, conditions) =
        PolicyRepo::update_with_policy(&state.db, id, &req, &policy).await?;
    let dto = PolicyDTO::from_policy_with_conditions(updated, conditions);
    invalidate_policy_cache_best_effort(state, dto.app_id).await;
    if dto.app_id != old_app_id {
        invalidate_policy_cache_best_effort(state, old_app_id).await;
    }
    Ok(dto)
}

pub async fn delete_policy_in_scope(
    state: &AppState,
    id: Uuid,
    scope: PolicyScope,
) -> Result<(), AppError> {
    let policy = load_policy_in_scope(state, id, scope).await?;
    PolicyRepo::delete(&state.db, id).await?;
    invalidate_policy_cache_best_effort(state, policy.app_id).await;
    Ok(())
}

pub async fn assign_policy_to_user_in_scope(
    state: &AppState,
    user_id: Uuid,
    policy_id: Uuid,
    scope: PolicyScope,
) -> Result<(), AppError> {
    let policy = load_policy_in_scope(state, policy_id, scope).await?;
    UserPolicyRepo::assign(&state.db, user_id, policy_id).await?;
    invalidate_policy_cache_best_effort(state, policy.app_id).await;
    Ok(())
}

pub async fn unassign_policy_from_user_in_scope(
    state: &AppState,
    user_id: Uuid,
    policy_id: Uuid,
    scope: PolicyScope,
) -> Result<(), AppError> {
    let policy = load_policy_in_scope(state, policy_id, scope).await?;
    UserPolicyRepo::unassign(&state.db, user_id, policy_id).await?;
    invalidate_policy_cache_best_effort(state, policy.app_id).await;
    Ok(())
}

pub async fn list_user_policy_dtos(
    state: &AppState,
    user_id: Uuid,
    scope: PolicyScope,
) -> Result<Vec<PolicyDTO>, AppError> {
    UserRepo::find_by_id_or_err(&state.db, user_id).await?;

    let app_id = match scope {
        PolicyScope::Any => None,
        PolicyScope::App(app_id) => Some(app_id),
    };
    let policies = PolicyRepo::select_policies(
        &state.db,
        PolicyFilter {
            user_id: Some(user_id),
            app_id,
            enabled_only: false,
        },
    )
    .await?;
    let attached = PolicyRepo::attach_conditions(&state.db, policies).await?;
    Ok(PolicyDTO::from_attached(attached))
}

pub async fn load_user_policies(
    state: &AppState,
    user_id: Uuid,
    app_id: Option<Uuid>,
    use_cache: bool,
) -> Result<AttachedPolicies, AppError> {
    let load = || async {
        let filter = PolicyFilter {
            user_id: Some(user_id),
            app_id,
            enabled_only: true,
        };
        let policies = PolicyRepo::select_policies(&state.db, filter).await?;
        PolicyRepo::attach_conditions(&state.db, policies).await
    };

    if !use_cache {
        return load().await;
    }

    let ttl = state.config.abac.policy_cache_ttl_seconds;

    match AbacCache::get_policies::<AttachedPolicies>(&state.cache, user_id, app_id).await {
        Ok(Some(cached)) => Ok(cached),
        _ => {
            let policies = load().await?;
            if let Err(e) =
                AbacCache::set_policies(&state.cache, user_id, app_id, &policies, ttl).await
            {
                tracing::warn!(error = %e, "failed to cache ABAC policies");
            }
            Ok(policies)
        }
    }
}

pub async fn invalidate_policy_cache_best_effort(state: &AppState, app_id: Option<Uuid>) {
    let ttl = state.config.abac.policy_cache_ttl_seconds;
    if let Err(e) = AbacCache::invalidate_policy_version(&state.cache, app_id, ttl).await {
        tracing::warn!(error = %e, app_id = ?app_id, "failed to invalidate ABAC policy cache");
    }
}

pub async fn invalidate_user_cache_best_effort(state: &AppState, user_id: Uuid) {
    let ttl = state.config.abac.policy_cache_ttl_seconds;
    if let Err(e) = AbacCache::invalidate_user_policy_version(&state.cache, user_id, ttl).await {
        tracing::warn!(error = %e, %user_id, "failed to invalidate ABAC user cache");
    }
}

async fn load_policy_in_scope(
    state: &AppState,
    id: Uuid,
    scope: PolicyScope,
) -> Result<Policy, AppError> {
    let policy = require_found(PolicyRepo::find_by_id(&state.db, id).await?, "policy")?;
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
