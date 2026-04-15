use axum::extract::{Path, State};
use axum::Json;
use crate::db::repos::{PolicyRepo, CreatePolicy, UpdatePolicy};
use crate::error::AppError;
use crate::extractors::ValidatedJson;
use crate::response::ApiResponse;
use crate::state::AppState;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct PolicyDetail {
    #[serde(flatten)]
    pub policy: crate::auth::abac::Policy,
    pub conditions: Vec<crate::auth::abac::PolicyCondition>,
}

pub async fn create_policy(
    State(state): State<AppState>,
    ValidatedJson(input): ValidatedJson<CreatePolicy>,
) -> Result<Json<ApiResponse<PolicyDetail>>, AppError> {
    let policy = PolicyRepo::create(&state.db, &input).await?;
    let conditions = PolicyRepo::get_conditions(&state.db, policy.id).await?;
    Ok(Json(ApiResponse::success(PolicyDetail { policy, conditions })))
}

pub async fn list_policies(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<Vec<crate::auth::abac::Policy>>>, AppError> {
    let policies = PolicyRepo::list(&state.db).await?;
    Ok(Json(ApiResponse::success(policies)))
}

pub async fn get_policy(
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<ApiResponse<PolicyDetail>>, AppError> {
    let policy = PolicyRepo::find_by_id(&state.db, id)
        .await?
        .ok_or(AppError::NotFound("policy".into()))?;
    let conditions = PolicyRepo::get_conditions(&state.db, id).await?;
    Ok(Json(ApiResponse::success(PolicyDetail { policy, conditions })))
}

pub async fn update_policy(
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
    ValidatedJson(input): ValidatedJson<UpdatePolicy>,
) -> Result<Json<ApiResponse<PolicyDetail>>, AppError> {
    let policy = PolicyRepo::update(&state.db, id, &input).await?;
    let conditions = PolicyRepo::get_conditions(&state.db, id).await?;
    Ok(Json(ApiResponse::success(PolicyDetail { policy, conditions })))
}

pub async fn delete_policy(
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<ApiResponse<()>>, AppError> {
    PolicyRepo::delete(&state.db, id).await?;
    Ok(Json(ApiResponse::<()>::success_message("policy deleted")))
}
