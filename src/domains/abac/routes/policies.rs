use crate::domains::abac::models::{
    CreatePolicyRequest, Policy, PolicyCondition, UpdatePolicyRequest,
};
use crate::domains::abac::repos::PolicyRepo;
use crate::shared::error::AppError;
use crate::shared::extractors::{Pagination, ValidatedJson};
use crate::shared::response::{ApiResponse, PageData};
use crate::shared::state::AppState;
use axum::Json;
use axum::extract::{Path, State};
use serde::Serialize;
use uuid::Uuid;

#[derive(Debug, Serialize)]
pub struct PolicyDTO {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub effect: String,
    pub priority: i32,
    pub enabled: bool,
    pub app_id: Option<Uuid>,
    pub created_at: chrono::DateTime<chrono::Utc>,
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
            conditions,
        }
    }
}

async fn invalidate_policy_cache(state: &AppState, app_id: Option<Uuid>) -> Result<(), AppError> {
    use redis::AsyncCommands;
    let mut conn = state.cache.clone();

    let patterns: Vec<String> = if app_id.is_some() {
        vec![format!("abac:*:{}", app_id.unwrap()), "abac:*:".to_string()]
    } else {
        vec!["abac:*:".to_string()]
    };

    for pattern in patterns {
        let mut cursor: u64 = 0;
        loop {
            let (new_cursor, keys): (u64, Vec<String>) = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg(&pattern)
                .arg("COUNT")
                .arg(100)
                .query_async(&mut conn)
                .await?;
            if !keys.is_empty() {
                let _: () = conn.del(&keys).await?;
            }
            cursor = new_cursor;
            if cursor == 0 {
                break;
            }
        }
    }
    Ok(())
}

pub async fn create_policy(
    State(state): State<AppState>,
    ValidatedJson(req): ValidatedJson<CreatePolicyRequest>,
) -> Result<Json<ApiResponse<PolicyDTO>>, AppError> {
    let policy = PolicyRepo::create(&state.db, &req).await?;
    let dto = PolicyDTO::from_policy(&state.db, policy.clone()).await?;
    invalidate_policy_cache(&state, req.app_id).await?;
    Ok(Json(ApiResponse::success(dto)))
}

pub async fn list_policies(
    State(state): State<AppState>,
    Pagination { page, page_size }: Pagination,
) -> Result<Json<ApiResponse<PageData<PolicyDTO>>>, AppError> {
    let (policies, total) = PolicyRepo::list(&state.db, page, page_size).await?;
    let ids: Vec<uuid::Uuid> = policies.iter().map(|p| p.id).collect();
    let conditions_map = PolicyRepo::batch_get_conditions_map(&state.db, &ids).await?;
    let items: Vec<PolicyDTO> = policies
        .into_iter()
        .map(|p| {
            let conditions = conditions_map.get(&p.id).cloned().unwrap_or_default();
            PolicyDTO::from_policy_with_conditions(p, conditions)
        })
        .collect();
    Ok(Json(ApiResponse::success(PageData::new(
        items, total, page, page_size,
    ))))
}

pub async fn get_policy(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<PolicyDTO>>, AppError> {
    let policy = PolicyRepo::find_by_id(&state.db, id)
        .await?
        .ok_or(AppError::NotFound("policy".into()))?;
    let dto = PolicyDTO::from_policy(&state.db, policy).await?;
    Ok(Json(ApiResponse::success(dto)))
}

pub async fn update_policy(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    ValidatedJson(req): ValidatedJson<UpdatePolicyRequest>,
) -> Result<Json<ApiResponse<PolicyDTO>>, AppError> {
    let updated = PolicyRepo::update(&state.db, id, &req).await?;
    let dto = PolicyDTO::from_policy(&state.db, updated.clone()).await?;
    invalidate_policy_cache(&state, updated.app_id).await?;
    Ok(Json(ApiResponse::success(dto)))
}

pub async fn delete_policy(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<()>>, AppError> {
    let policy = PolicyRepo::find_by_id(&state.db, id)
        .await?
        .ok_or(AppError::NotFound("policy".into()))?;
    PolicyRepo::delete(&state.db, id).await?;
    invalidate_policy_cache(&state, policy.app_id).await?;
    Ok(Json(ApiResponse::<()>::success_message("policy deleted")))
}

pub async fn assign_policy(
    State(state): State<AppState>,
    Path((user_id, policy_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<ApiResponse<()>>, AppError> {
    PolicyRepo::assign_policy_to_user(&state.db, user_id, policy_id).await?;
    let policy = PolicyRepo::find_by_id(&state.db, policy_id).await?;
    invalidate_policy_cache(&state, policy.and_then(|p| p.app_id)).await?;
    Ok(Json(ApiResponse::<()>::success_message("policy assigned")))
}

pub async fn unassign_policy(
    State(state): State<AppState>,
    Path((user_id, policy_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<ApiResponse<()>>, AppError> {
    let policy = PolicyRepo::find_by_id(&state.db, policy_id).await?;
    PolicyRepo::unassign_policy_from_user(&state.db, user_id, policy_id).await?;
    invalidate_policy_cache(&state, policy.and_then(|p| p.app_id)).await?;
    Ok(Json(ApiResponse::<()>::success_message(
        "policy unassigned",
    )))
}

pub async fn list_user_policies(
    State(state): State<AppState>,
    Path(user_id): Path<Uuid>,
) -> Result<Json<ApiResponse<Vec<PolicyDTO>>>, AppError> {
    let policies = PolicyRepo::list_user_assignments(&state.db, user_id).await?;
    let ids: Vec<Uuid> = policies.iter().map(|p| p.id).collect();
    let conditions_map = PolicyRepo::batch_get_conditions_map(&state.db, &ids).await?;
    let items: Vec<PolicyDTO> = policies
        .into_iter()
        .map(|p| {
            let conditions = conditions_map.get(&p.id).cloned().unwrap_or_default();
            PolicyDTO::from_policy_with_conditions(p, conditions)
        })
        .collect();
    Ok(Json(ApiResponse::success(items)))
}
