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
    security(("bearer_auth" = [])),
    request_body = CreatePolicyRequest,
    responses(
        (status = 200, description = "Policy created", body = ApiResponse<PolicyDTO>),
        (status = 401, description = "Unauthorized"),
    )
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
    pag: Pagination,
) -> Result<Json<ApiResponse<PageData<PolicyDTO>>>, AppError> {
    handlers::list(&state, PolicyScope::Any, pag).await
}

#[utoipa::path(
    get,
    path = "/api/policies/{id}",
    tag = "ABAC",
    security(("bearer_auth" = [])),
    params(("id" = uuid::Uuid, Path, description = "Policy ID")),
    responses(
        (status = 200, description = "Policy details", body = ApiResponse<PolicyDTO>),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Policy not found"),
    )
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
    security(("bearer_auth" = [])),
    params(("id" = uuid::Uuid, Path, description = "Policy ID")),
    request_body = UpdatePolicyRequest,
    responses(
        (status = 200, description = "Policy updated", body = ApiResponse<PolicyDTO>),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Policy not found"),
    )
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
    security(("bearer_auth" = [])),
    params(("id" = uuid::Uuid, Path, description = "Policy ID")),
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
    handlers::delete(&state, id, PolicyScope::Any).await
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
    handlers::assign(&state, user_id, policy_id, PolicyScope::Any).await
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
    handlers::unassign(&state, user_id, policy_id, PolicyScope::Any).await
}

#[utoipa::path(
    get,
    path = "/api/users/{user_id}/policies",
    tag = "ABAC",
    security(("bearer_auth" = [])),
    params(("user_id" = uuid::Uuid, Path, description = "User ID")),
    responses(
        (status = 200, description = "User policies"),
        (status = 401, description = "Unauthorized"),
    )
)]
pub async fn list_user_policies(
    State(state): State<AppState>,
    Path(user_id): Path<Uuid>,
) -> Result<Json<ApiResponse<Vec<PolicyDTO>>>, AppError> {
    handlers::list_user_policies(&state, user_id, PolicyScope::Any).await
}
