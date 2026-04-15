use axum::extract::{Path, State};
use axum::Json;
use serde::Serialize;
use uuid::Uuid;
use crate::domains::abac::models::{Policy, PolicyCondition, CreatePolicyRequest, UpdatePolicyRequest};
use crate::domains::abac::repos::PolicyRepo;
use crate::shared::error::AppError;
use crate::shared::extractors::{ValidatedJson, Pagination};
use crate::shared::response::{ApiResponse, PageData};
use crate::shared::state::AppState;

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
    pub async fn from_policy(pool: &sqlx::postgres::PgPool, policy: Policy) -> Result<Self, AppError> {
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
}

pub async fn create_policy(
    State(state): State<AppState>,
    ValidatedJson(req): ValidatedJson<CreatePolicyRequest>,
) -> Result<Json<ApiResponse<PolicyDTO>>, AppError> {
    let policy = PolicyRepo::create(&state.db, &req).await?;
    let dto = PolicyDTO::from_policy(&state.db, policy).await?;
    Ok(Json(ApiResponse::success(dto)))
}

pub async fn list_policies(
    State(state): State<AppState>,
    Pagination { page, page_size }: Pagination,
) -> Result<Json<ApiResponse<PageData<PolicyDTO>>>, AppError> {
    let (policies, total) = PolicyRepo::list(&state.db, page, page_size).await?;
    let mut items = Vec::new();
    for policy in policies {
        items.push(PolicyDTO::from_policy(&state.db, policy).await?);
    }
    Ok(Json(ApiResponse::success(PageData::new(items, total, page, page_size))))
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
    let policy = PolicyRepo::update(&state.db, id, &req).await?;
    let dto = PolicyDTO::from_policy(&state.db, policy).await?;
    Ok(Json(ApiResponse::success(dto)))
}

pub async fn delete_policy(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<()>>, AppError> {
    PolicyRepo::delete(&state.db, id).await?;
    Ok(Json(ApiResponse::<()>::success_message("policy deleted")))
}
