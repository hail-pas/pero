use crate::domains::abac::models::{CreatePolicyRequest, UpdatePolicyRequest};
use crate::domains::abac::repos::PolicyRepo;
use crate::domains::oauth2::models::OAuth2Client;
use crate::shared::error::AppError;
use crate::shared::extractors::{Pagination, ValidatedJson};
use crate::shared::response::{ApiResponse, PageData};
use crate::shared::state::AppState;
use axum::Json;
use axum::extract::{Path, State};
use uuid::Uuid;

use super::common::{
    PolicyDTO, PolicyScope, assign_policy_to_user_in_scope, build_policy_page, create_policy_dto,
    delete_policy_in_scope, get_policy_dto, list_user_policy_dtos,
    unassign_policy_from_user_in_scope, update_policy_dto,
};

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
    axum::Extension(client): axum::Extension<OAuth2Client>,
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
    axum::Extension(client): axum::Extension<OAuth2Client>,
    Pagination { page, page_size }: Pagination,
) -> Result<Json<ApiResponse<PageData<PolicyDTO>>>, AppError> {
    let (policies, total) =
        PolicyRepo::list_by_app(&state.db, client.app_id, page, page_size).await?;
    let data = build_policy_page(&state, policies, total, page, page_size).await?;
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
    axum::Extension(client): axum::Extension<OAuth2Client>,
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
    axum::Extension(client): axum::Extension<OAuth2Client>,
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
        (status = 200, description = "Policy deleted", body = serde_json::Value),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Policy not found"),
    )
)]
pub async fn delete_policy(
    State(state): State<AppState>,
    axum::Extension(client): axum::Extension<OAuth2Client>,
    Path(id): Path<Uuid>,
) -> Result<Json<ApiResponse<()>>, AppError> {
    delete_policy_in_scope(&state, id, PolicyScope::App(client.app_id)).await?;
    Ok(Json(ApiResponse::<()>::success_message("policy deleted")))
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
        (status = 200, description = "Policy assigned", body = serde_json::Value),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "User or policy not found"),
    )
)]
pub async fn assign_policy(
    State(state): State<AppState>,
    axum::Extension(client): axum::Extension<OAuth2Client>,
    Path((user_id, policy_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<ApiResponse<()>>, AppError> {
    assign_policy_to_user_in_scope(&state, user_id, policy_id, PolicyScope::App(client.app_id))
        .await?;
    Ok(Json(ApiResponse::<()>::success_message("policy assigned")))
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
        (status = 200, description = "Policy unassigned", body = serde_json::Value),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Assignment not found"),
    )
)]
pub async fn unassign_policy(
    State(state): State<AppState>,
    axum::Extension(client): axum::Extension<OAuth2Client>,
    Path((user_id, policy_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<ApiResponse<()>>, AppError> {
    unassign_policy_from_user_in_scope(&state, user_id, policy_id, PolicyScope::App(client.app_id))
        .await?;
    Ok(Json(ApiResponse::<()>::success_message(
        "policy unassigned",
    )))
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
    axum::Extension(client): axum::Extension<OAuth2Client>,
    Path(user_id): Path<Uuid>,
) -> Result<Json<ApiResponse<Vec<PolicyDTO>>>, AppError> {
    let items = list_user_policy_dtos(&state, user_id, PolicyScope::App(client.app_id)).await?;
    Ok(Json(ApiResponse::success(items)))
}
