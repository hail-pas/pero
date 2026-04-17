use crate::domains::abac::models::{
    CreatePolicyRequest, Policy, PolicyCondition, UpdatePolicyRequest,
};
use crate::domains::abac::repos::PolicyRepo;
use crate::domains::identity::repos::UserRepo;
use crate::shared::constants::cache_keys;
use crate::shared::error::AppError;
use crate::shared::response::PageData;
use crate::shared::state::AppState;
use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;

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
    pub async fn from_policy(
        pool: &sqlx::postgres::PgPool,
        policy: Policy,
    ) -> Result<Self, AppError> {
        let conditions = PolicyRepo::get_conditions(pool, policy.id).await?;
        Ok(Self {
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
        })
    }

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
            .map(|(p, conds)| Self::from_policy_with_conditions(p, conds))
            .collect()
    }
}

#[derive(Debug, Clone, Copy)]
pub enum PolicyScope {
    Any,
    App(Uuid),
}

pub async fn invalidate_policy_cache(
    state: &AppState,
    app_id: Option<Uuid>,
) -> Result<(), AppError> {
    let patterns: Vec<String> = if let Some(aid) = app_id {
        vec![
            format!("{}*:{}", cache_keys::ABAC_PREFIX, aid),
            format!("{}*:", cache_keys::ABAC_PREFIX),
        ]
    } else {
        vec![format!("{}*", cache_keys::ABAC_PREFIX)]
    };
    for pattern in patterns {
        crate::cache::delete_by_pattern(&state.cache, &pattern).await?;
    }
    Ok(())
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
    invalidate_policy_cache(state, dto.app_id).await?;
    Ok(dto)
}

pub async fn build_policy_page(
    state: &AppState,
    policies: Vec<Policy>,
    total: i64,
    page: i64,
    page_size: i64,
) -> Result<PageData<PolicyDTO>, AppError> {
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
    PolicyDTO::from_policy(&state.db, policy).await
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
        req.app_id = Some(app_id);
    }
    let (updated, conditions) =
        PolicyRepo::update_with_policy(&state.db, id, &req, &policy).await?;
    let dto = PolicyDTO::from_policy_with_conditions(updated, conditions);
    invalidate_policy_cache(state, dto.app_id).await?;
    Ok(dto)
}

pub async fn delete_policy_in_scope(
    state: &AppState,
    id: Uuid,
    scope: PolicyScope,
) -> Result<(), AppError> {
    let policy = load_policy_in_scope(state, id, scope).await?;
    PolicyRepo::delete(&state.db, id).await?;
    invalidate_policy_cache(state, policy.app_id).await
}

pub async fn assign_policy_to_user_in_scope(
    state: &AppState,
    user_id: Uuid,
    policy_id: Uuid,
    scope: PolicyScope,
) -> Result<(), AppError> {
    let policy = load_policy_in_scope(state, policy_id, scope).await?;
    PolicyRepo::assign_policy_to_user(&state.db, user_id, policy_id).await?;
    invalidate_policy_cache(state, policy.app_id).await
}

pub async fn unassign_policy_from_user_in_scope(
    state: &AppState,
    user_id: Uuid,
    policy_id: Uuid,
    scope: PolicyScope,
) -> Result<(), AppError> {
    let policy = load_policy_in_scope(state, policy_id, scope).await?;
    PolicyRepo::unassign_policy_from_user(&state.db, user_id, policy_id).await?;
    invalidate_policy_cache(state, policy.app_id).await
}

pub async fn list_user_policy_dtos(
    state: &AppState,
    user_id: Uuid,
    scope: PolicyScope,
) -> Result<Vec<PolicyDTO>, AppError> {
    UserRepo::find_by_id_or_err(&state.db, user_id).await?;

    let policies = match scope {
        PolicyScope::Any => PolicyRepo::list_user_assignments(&state.db, user_id).await?,
        PolicyScope::App(app_id) => {
            PolicyRepo::list_user_policies_by_app(&state.db, user_id, app_id).await?
        }
    };
    let attached = PolicyRepo::attach_conditions(&state.db, policies).await?;
    Ok(PolicyDTO::from_attached(attached))
}

async fn load_policy_in_scope(
    state: &AppState,
    id: Uuid,
    scope: PolicyScope,
) -> Result<Policy, AppError> {
    let policy = PolicyRepo::find_by_id(&state.db, id)
        .await?
        .ok_or(AppError::NotFound("policy".into()))?;
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
