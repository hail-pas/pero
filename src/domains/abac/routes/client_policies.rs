use crate::domains::abac::models::{CreatePolicyRequest, UpdatePolicyRequest};
use crate::domains::abac::service::{
    PolicyDTO, PolicyScope, assign_policy_to_user_in_scope, create_policy_dto,
    delete_policy_in_scope, get_policy_dto, list_policy_page, list_user_policy_dtos,
    unassign_policy_from_user_in_scope, update_policy_dto,
};
use crate::shared::error::AppError;
use crate::shared::extractors::{AuthClient, Pagination, ValidatedJson};
use crate::shared::response::{ApiResponse, MessageResponse};
use crate::shared::state::AppState;
use axum::Json;
use axum::extract::{Path, State};
use uuid::Uuid;

#[utoipa::path(
    post,
    path = "/api/client/policies",
    tag = "Client ABAC",
    security(("basic_auth" = [])),
    request_body = CreatePolicyRequest,
    responses(
        (status = 200, description = "Policy created", body = ApiResponse<PolicyDTO>),
        (status = 401, description = "Unauthorized"),
    )
)]
pub async fn create_policy(
    State(state): State<AppState>,
    AuthClient(client): AuthClient,
    ValidatedJson(req): ValidatedJson<CreatePolicyRequest>,
) -> Result<Json<ApiResponse<PolicyDTO>>, AppError> {
    let dto = create_policy_dto(&state, req, Some(client.app_id)).await?;
    Ok(Json(ApiResponse::success(dto)))
}

#[utoipa::path(
    get,
    path = "/api/client/policies",
    tag = "Client ABAC",
    security(("basic_auth" = [])),
    params(
        ("page" = Option<i64>, Query, description = "Page number"),
        ("page_size" = Option<i64>, Query, description = "Page size"),
    ),
    responses(
        (status = 200, description = "Policy list"),
        (status = 401, description = "Unauthorized"),
    )
)]
pub async fn list_policies(
    State(state): State<AppState>,
    AuthClient(client): AuthClient,
    Pagination { page, page_size }: Pagination,
) -> Result<Json<ApiResponse<crate::shared::response::PageData<PolicyDTO>>>, AppError> {
    let data = list_policy_page(&state, PolicyScope::App(client.app_id), page, page_size).await?;
    Ok(Json(ApiResponse::success(data)))
}

#[utoipa::path(
    get,
    path = "/api/client/policies/{id}",
    tag = "Client ABAC",
    security(("basic_auth" = [])),
    params(("id" = Uuid, Path, description = "Policy ID")),
    responses(
        (status = 200, description = "Policy details", body = ApiResponse<PolicyDTO>),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Policy not found"),
    )
)]
pub async fn get_policy(
    State(state): State<AppState>,
    AuthClient(client): AuthClient,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<PolicyDTO>>, AppError> {
    let dto = get_policy_dto(&state, id, PolicyScope::App(client.app_id)).await?;
    Ok(Json(ApiResponse::success(dto)))
}

#[utoipa::path(
    put,
    path = "/api/client/policies/{id}",
    tag = "Client ABAC",
    security(("basic_auth" = [])),
    params(("id" = Uuid, Path, description = "Policy ID")),
    request_body = UpdatePolicyRequest,
    responses(
        (status = 200, description = "Policy updated", body = ApiResponse<PolicyDTO>),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Policy not found"),
    )
)]
pub async fn update_policy(
    State(state): State<AppState>,
    AuthClient(client): AuthClient,
    Path(id): Path<Uuid>,
    ValidatedJson(req): ValidatedJson<UpdatePolicyRequest>,
) -> Result<Json<ApiResponse<PolicyDTO>>, AppError> {
    let dto = update_policy_dto(
        &state,
        id,
        req,
        PolicyScope::App(client.app_id),
        Some(client.app_id),
    )
    .await?;
    Ok(Json(ApiResponse::success(dto)))
}

#[utoipa::path(
    delete,
    path = "/api/client/policies/{id}",
    tag = "Client ABAC",
    security(("basic_auth" = [])),
    params(("id" = Uuid, Path, description = "Policy ID")),
    responses(
        (status = 200, description = "Policy deleted", body = MessageResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Policy not found"),
    )
)]
pub async fn delete_policy(
    State(state): State<AppState>,
    AuthClient(client): AuthClient,
    Path(id): Path<Uuid>,
) -> Result<Json<MessageResponse>, AppError> {
    delete_policy_in_scope(&state, id, PolicyScope::App(client.app_id)).await?;
    Ok(Json(MessageResponse::success("policy deleted")))
}

#[utoipa::path(
    post,
    path = "/api/client/users/{user_id}/policies/{policy_id}",
    tag = "Client ABAC",
    security(("basic_auth" = [])),
    params(
        ("user_id" = Uuid, Path, description = "User ID"),
        ("policy_id" = Uuid, Path, description = "Policy ID"),
    ),
    responses(
        (status = 200, description = "Policy assigned", body = MessageResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "User or policy not found"),
    )
)]
pub async fn assign_policy(
    State(state): State<AppState>,
    AuthClient(client): AuthClient,
    Path((user_id, policy_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<MessageResponse>, AppError> {
    assign_policy_to_user_in_scope(&state, user_id, policy_id, PolicyScope::App(client.app_id))
        .await?;
    Ok(Json(MessageResponse::success("policy assigned")))
}

#[utoipa::path(
    delete,
    path = "/api/client/users/{user_id}/policies/{policy_id}",
    tag = "Client ABAC",
    security(("basic_auth" = [])),
    params(
        ("user_id" = Uuid, Path, description = "User ID"),
        ("policy_id" = Uuid, Path, description = "Policy ID"),
    ),
    responses(
        (status = 200, description = "Policy unassigned", body = MessageResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Assignment not found"),
    )
)]
pub async fn unassign_policy(
    State(state): State<AppState>,
    AuthClient(client): AuthClient,
    Path((user_id, policy_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<MessageResponse>, AppError> {
    unassign_policy_from_user_in_scope(&state, user_id, policy_id, PolicyScope::App(client.app_id))
        .await?;
    Ok(Json(MessageResponse::success("policy unassigned")))
}

#[utoipa::path(
    get,
    path = "/api/client/users/{user_id}/policies",
    tag = "Client ABAC",
    security(("basic_auth" = [])),
    params(("user_id" = Uuid, Path, description = "User ID")),
    responses(
        (status = 200, description = "User policies"),
        (status = 401, description = "Unauthorized"),
    )
)]
pub async fn list_user_policies(
    State(state): State<AppState>,
    AuthClient(client): AuthClient,
    Path(user_id): Path<Uuid>,
) -> Result<Json<ApiResponse<Vec<PolicyDTO>>>, AppError> {
    let items = list_user_policy_dtos(&state, user_id, PolicyScope::App(client.app_id)).await?;
    Ok(Json(ApiResponse::success(items)))
}
