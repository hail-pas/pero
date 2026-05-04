use crate::api::extractors::{Pagination, ValidatedJson};
use crate::api::response::{ApiResponse, MessageResponse, PageData};
use crate::domain::abac::models::{CreatePolicyRequest, UpdatePolicyRequest};
use crate::domain::abac::service::PolicyDTO;
use crate::domain::abac::service::PolicyScope;
use crate::handler::abac::handlers;
use crate::shared::error::AppError;
use crate::shared::state::AppState;
use axum::Json;
use axum::extract::{Path, State};
use uuid::Uuid;

#[utoipa::path(
    post,
    path = "/api/policies",
    tag = "ABAC",
    request_body = crate::api::schemas::abac::CreatePolicyRequest,
    responses(
        (status = 200, description = "Policy created", body = crate::api::response::ApiResponse<crate::api::schemas::abac::PolicyDTO>),
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_policy(
    State(state): State<AppState>,
    ValidatedJson(req): ValidatedJson<CreatePolicyRequest>,
) -> Result<Json<ApiResponse<PolicyDTO>>, AppError> {
    handlers::create(&state, req, PolicyScope::Any, None).await
}

#[utoipa::path(
    get,
    path = "/api/policies",
    tag = "ABAC",
    params(
        ("page" = Option<i64>, Query, description = "Page number"),
        ("page_size" = Option<i64>, Query, description = "Page size"),
    ),
    responses(
        (status = 200, description = "Policy list", body = crate::api::response::ApiResponse<crate::api::response::PageData<crate::api::schemas::abac::PolicyDTO>>),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_policies(
    State(state): State<AppState>,
    pag: Pagination,
) -> Result<Json<ApiResponse<PageData<PolicyDTO>>>, AppError> {
    handlers::list(&state, PolicyScope::Any, pag).await
}

#[utoipa::path(
    get,
    path = "/api/policies/{id}",
    tag = "ABAC",
    params(
        ("id" = uuid::Uuid, Path, description = "Policy ID"),
    ),
    responses(
        (status = 200, description = "Policy detail", body = crate::api::response::ApiResponse<crate::api::schemas::abac::PolicyDTO>),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_policy(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<PolicyDTO>>, AppError> {
    handlers::get(&state, id, PolicyScope::Any).await
}

#[utoipa::path(
    put,
    path = "/api/policies/{id}",
    tag = "ABAC",
    params(
        ("id" = uuid::Uuid, Path, description = "Policy ID"),
    ),
    request_body = crate::api::schemas::abac::UpdatePolicyRequest,
    responses(
        (status = 200, description = "Policy updated", body = crate::api::response::ApiResponse<crate::api::schemas::abac::PolicyDTO>),
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_policy(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    ValidatedJson(req): ValidatedJson<UpdatePolicyRequest>,
) -> Result<Json<ApiResponse<PolicyDTO>>, AppError> {
    handlers::update(&state, id, req, PolicyScope::Any, None).await
}

#[utoipa::path(
    delete,
    path = "/api/policies/{id}",
    tag = "ABAC",
    params(
        ("id" = uuid::Uuid, Path, description = "Policy ID"),
    ),
    responses(
        (status = 200, description = "Policy deleted", body = crate::api::response::MessageResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_policy(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<MessageResponse>, AppError> {
    handlers::delete(&state, id, PolicyScope::Any).await
}

#[utoipa::path(
    post,
    path = "/api/users/{user_id}/policies/{policy_id}",
    tag = "ABAC",
    params(
        ("user_id" = uuid::Uuid, Path, description = "User ID"),
        ("policy_id" = uuid::Uuid, Path, description = "Policy ID"),
    ),
    responses(
        (status = 200, description = "Policy assigned", body = crate::api::response::MessageResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn assign_policy(
    State(state): State<AppState>,
    Path((user_id, policy_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<MessageResponse>, AppError> {
    handlers::assign(&state, user_id, policy_id, PolicyScope::Any).await
}

#[utoipa::path(
    delete,
    path = "/api/users/{user_id}/policies/{policy_id}",
    tag = "ABAC",
    params(
        ("user_id" = uuid::Uuid, Path, description = "User ID"),
        ("policy_id" = uuid::Uuid, Path, description = "Policy ID"),
    ),
    responses(
        (status = 200, description = "Policy unassigned", body = crate::api::response::MessageResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn unassign_policy(
    State(state): State<AppState>,
    Path((user_id, policy_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<MessageResponse>, AppError> {
    handlers::unassign(&state, user_id, policy_id, PolicyScope::Any).await
}

#[utoipa::path(
    get,
    path = "/api/users/{user_id}/policies",
    tag = "ABAC",
    params(
        ("user_id" = uuid::Uuid, Path, description = "User ID"),
    ),
    responses(
        (status = 200, description = "User policies", body = crate::api::response::ApiResponse<Vec<crate::api::schemas::abac::PolicyDTO>>),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_user_policies(
    State(state): State<AppState>,
    Path(user_id): Path<Uuid>,
) -> Result<Json<ApiResponse<Vec<PolicyDTO>>>, AppError> {
    handlers::list_user_policies(&state, user_id, PolicyScope::Any).await
}
