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

#[utoipa::path(
    post,
    path = "/api/policies",
    tag = "ABAC",
    security(("bearer_auth" = [])),
    request_body = crate::domains::abac::models::CreatePolicyRequest,
    responses(
        (status = 200, description = "Policy created", body = ApiResponse<crate::domains::abac::routes::policies::PolicyDTO>),
        (status = 401, description = "Unauthorized"),
    )
)]
pub async fn create_policy(
    State(state): State<AppState>,
    ValidatedJson(req): ValidatedJson<CreatePolicyRequest>,
) -> Result<Json<ApiResponse<PolicyDTO>>, AppError> {
    let policy = PolicyRepo::create(&state.db, &req).await?;
    let dto = PolicyDTO::from_policy(&state.db, policy.clone()).await?;
    invalidate_policy_cache(&state, req.app_id).await?;
    Ok(Json(ApiResponse::success(dto)))
}

#[utoipa::path(
    get,
    path = "/api/policies",
    tag = "ABAC",
    security(("bearer_auth" = [])),
    params(
        ("page" = i64, Query, description = "Page number"),
        ("page_size" = i64, Query, description = "Page size"),
    ),
    responses(
        (status = 200, description = "Policy list"),
        (status = 401, description = "Unauthorized"),
    )
)]
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

#[utoipa::path(
    get,
    path = "/api/policies/{id}",
    tag = "ABAC",
    security(("bearer_auth" = [])),
    params(
        ("id" = uuid::Uuid, Path, description = "Policy ID"),
    ),
    responses(
        (status = 200, description = "Policy details", body = ApiResponse<crate::domains::abac::routes::policies::PolicyDTO>),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Policy not found"),
    )
)]
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

#[utoipa::path(
    put,
    path = "/api/policies/{id}",
    tag = "ABAC",
    security(("bearer_auth" = [])),
    params(
        ("id" = uuid::Uuid, Path, description = "Policy ID"),
    ),
    request_body = crate::domains::abac::models::UpdatePolicyRequest,
    responses(
        (status = 200, description = "Policy updated", body = ApiResponse<crate::domains::abac::routes::policies::PolicyDTO>),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Policy not found"),
    )
)]
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

#[utoipa::path(
    delete,
    path = "/api/policies/{id}",
    tag = "ABAC",
    security(("bearer_auth" = [])),
    params(
        ("id" = uuid::Uuid, Path, description = "Policy ID"),
    ),
    responses(
        (status = 200, description = "Policy deleted", body = serde_json::Value),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Policy not found"),
    )
)]
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

#[utoipa::path(
    post,
    path = "/api/users/{user_id}/policies/{policy_id}",
    tag = "ABAC",
    security(("bearer_auth" = [])),
    params(
        ("user_id" = uuid::Uuid, Path, description = "User ID"),
        ("policy_id" = uuid::Uuid, Path, description = "Policy ID"),
    ),
    responses(
        (status = 200, description = "Policy assigned", body = serde_json::Value),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "User or policy not found"),
    )
)]
pub async fn assign_policy(
    State(state): State<AppState>,
    Path((user_id, policy_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<ApiResponse<()>>, AppError> {
    PolicyRepo::assign_policy_to_user(&state.db, user_id, policy_id).await?;
    let policy = PolicyRepo::find_by_id(&state.db, policy_id).await?;
    invalidate_policy_cache(&state, policy.and_then(|p| p.app_id)).await?;
    Ok(Json(ApiResponse::<()>::success_message("policy assigned")))
}

#[utoipa::path(
    delete,
    path = "/api/users/{user_id}/policies/{policy_id}",
    tag = "ABAC",
    security(("bearer_auth" = [])),
    params(
        ("user_id" = uuid::Uuid, Path, description = "User ID"),
        ("policy_id" = uuid::Uuid, Path, description = "Policy ID"),
    ),
    responses(
        (status = 200, description = "Policy unassigned", body = serde_json::Value),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Assignment not found"),
    )
)]
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

#[utoipa::path(
    get,
    path = "/api/users/{user_id}/policies",
    tag = "ABAC",
    security(("bearer_auth" = [])),
    params(
        ("user_id" = uuid::Uuid, Path, description = "User ID"),
    ),
    responses(
        (status = 200, description = "User policies"),
        (status = 401, description = "Unauthorized"),
    )
)]
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
