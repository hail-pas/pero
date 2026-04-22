use crate::domains::abac::models::{CreatePolicyRequest, UpdatePolicyRequest};
pub use crate::domains::abac::service::PolicyDTO;
use crate::domains::abac::service::{
    PolicyScope, assign_policy_to_user_in_scope, create_policy_dto, delete_policy_in_scope,
    get_policy_dto, list_policy_page, list_user_policy_dtos, unassign_policy_from_user_in_scope,
    update_policy_dto,
};
use crate::shared::error::AppError;
use crate::shared::extractors::{Pagination, ValidatedJson};
use crate::shared::response::{ApiResponse, MessageResponse};
use crate::shared::state::AppState;
use axum::Json;
use axum::extract::{Path, State};
use uuid::Uuid;

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
    let dto = create_policy_dto(&state, req, None).await?;
    Ok(Json(ApiResponse::success(dto)))
}

#[utoipa::path(
    get,
    path = "/api/policies",
    tag = "ABAC",
    security(("bearer_auth" = [])),
    params(
        ("page" = Option<i64>, Query, description = "Page number (default: 1)"),
        ("page_size" = Option<i64>, Query, description = "Page size (default: 10)"),
    ),
    responses(
        (status = 200, description = "Policy list"),
        (status = 401, description = "Unauthorized"),
    )
)]
pub async fn list_policies(
    State(state): State<AppState>,
    Pagination { page, page_size }: Pagination,
) -> Result<Json<ApiResponse<crate::shared::response::PageData<PolicyDTO>>>, AppError> {
    let data = list_policy_page(&state, PolicyScope::Any, page, page_size).await?;
    Ok(Json(ApiResponse::success(data)))
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
    let dto = get_policy_dto(&state, id, PolicyScope::Any).await?;
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
    let dto = update_policy_dto(&state, id, req, PolicyScope::Any, None).await?;
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
        (status = 200, description = "Policy deleted", body = MessageResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Policy not found"),
    )
)]
pub async fn delete_policy(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<MessageResponse>, AppError> {
    delete_policy_in_scope(&state, id, PolicyScope::Any).await?;
    Ok(Json(MessageResponse::success("policy deleted")))
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
        (status = 200, description = "Policy assigned", body = MessageResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "User or policy not found"),
    )
)]
pub async fn assign_policy(
    State(state): State<AppState>,
    Path((user_id, policy_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<MessageResponse>, AppError> {
    assign_policy_to_user_in_scope(&state, user_id, policy_id, PolicyScope::Any).await?;
    Ok(Json(MessageResponse::success("policy assigned")))
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
        (status = 200, description = "Policy unassigned", body = MessageResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Assignment not found"),
    )
)]
pub async fn unassign_policy(
    State(state): State<AppState>,
    Path((user_id, policy_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<MessageResponse>, AppError> {
    unassign_policy_from_user_in_scope(&state, user_id, policy_id, PolicyScope::Any).await?;
    Ok(Json(MessageResponse::success("policy unassigned")))
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
    let items = list_user_policy_dtos(&state, user_id, PolicyScope::Any).await?;
    Ok(Json(ApiResponse::success(items)))
}
