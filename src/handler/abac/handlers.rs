use crate::api::extractors::Pagination;
use crate::api::response::{ApiResponse, MessageResponse, PageData};
use crate::domain::abac::models::{CreatePolicyRequest, UpdatePolicyRequest};
pub use crate::domain::abac::service::PolicyDTO;
use crate::domain::abac::service::{
    PolicyScope, assign_policy_to_user_in_scope, create_policy_dto, delete_policy_in_scope,
    get_policy_dto, list_policy_page, list_user_policy_dtos, unassign_policy_from_user_in_scope,
    update_policy_dto,
};
use crate::shared::error::AppError;
use crate::shared::state::AppState;
use axum::Json;
use uuid::Uuid;

pub async fn create(
    state: &AppState,
    req: CreatePolicyRequest,
    _scope: PolicyScope,
    forced_app_id: Option<uuid::Uuid>,
) -> Result<Json<ApiResponse<PolicyDTO>>, AppError> {
    let dto = create_policy_dto(
        &*state.repos.policies,
        &*state.repos.abac_cache,
        state.config.abac.policy_cache_ttl_seconds,
        req,
        forced_app_id,
    )
    .await?;
    Ok(Json(ApiResponse::success(dto)))
}

pub async fn list(
    state: &AppState,
    scope: PolicyScope,
    Pagination { page, page_size }: Pagination,
) -> Result<Json<ApiResponse<crate::api::response::PageData<PolicyDTO>>>, AppError> {
    let (items, total) = list_policy_page(&*state.repos.policies, scope, page, page_size).await?;
    Ok(Json(ApiResponse::success(PageData::new(
        items, total, page, page_size,
    ))))
}

pub async fn get(
    state: &AppState,
    id: Uuid,
    scope: PolicyScope,
) -> Result<Json<ApiResponse<PolicyDTO>>, AppError> {
    let dto = get_policy_dto(&*state.repos.policies, id, scope).await?;
    Ok(Json(ApiResponse::success(dto)))
}

pub async fn update(
    state: &AppState,
    id: Uuid,
    req: UpdatePolicyRequest,
    scope: PolicyScope,
    forced_app_id: Option<Uuid>,
) -> Result<Json<ApiResponse<PolicyDTO>>, AppError> {
    let dto = update_policy_dto(
        &*state.repos.policies,
        &*state.repos.abac_cache,
        state.config.abac.policy_cache_ttl_seconds,
        id,
        req,
        scope,
        forced_app_id,
    )
    .await?;
    Ok(Json(ApiResponse::success(dto)))
}

pub async fn delete(
    state: &AppState,
    id: Uuid,
    scope: PolicyScope,
) -> Result<Json<MessageResponse>, AppError> {
    delete_policy_in_scope(
        &*state.repos.policies,
        &*state.repos.abac_cache,
        state.config.abac.policy_cache_ttl_seconds,
        id,
        scope,
    )
    .await?;
    Ok(Json(MessageResponse::success("policy deleted")))
}

pub async fn assign(
    state: &AppState,
    user_id: Uuid,
    policy_id: Uuid,
    scope: PolicyScope,
) -> Result<Json<MessageResponse>, AppError> {
    assign_policy_to_user_in_scope(
        &*state.repos.policies,
        &*state.repos.abac_cache,
        state.config.abac.policy_cache_ttl_seconds,
        user_id,
        policy_id,
        scope,
    )
    .await?;
    Ok(Json(MessageResponse::success("policy assigned")))
}

pub async fn unassign(
    state: &AppState,
    user_id: Uuid,
    policy_id: Uuid,
    scope: PolicyScope,
) -> Result<Json<MessageResponse>, AppError> {
    unassign_policy_from_user_in_scope(
        &*state.repos.policies,
        &*state.repos.abac_cache,
        state.config.abac.policy_cache_ttl_seconds,
        user_id,
        policy_id,
        scope,
    )
    .await?;
    Ok(Json(MessageResponse::success("policy unassigned")))
}

pub async fn list_user_policies(
    state: &AppState,
    user_id: Uuid,
    scope: PolicyScope,
) -> Result<Json<ApiResponse<Vec<PolicyDTO>>>, AppError> {
    let items =
        list_user_policy_dtos(&*state.repos.users, &*state.repos.policies, user_id, scope).await?;
    Ok(Json(ApiResponse::success(items)))
}
