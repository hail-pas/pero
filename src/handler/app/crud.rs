use axum::Json;
use axum::extract::{Path, State};

use crate::domain::app::models::{AppDTO, CreateAppRequest, UpdateAppRequest};
use crate::domain::app::service;
use crate::shared::error::AppError;
use crate::api::extractors::{Pagination, ValidatedJson};
use crate::api::response::{ApiResponse, MessageResponse, PageData};
use crate::shared::state::AppState;

#[utoipa::path(
    post,
    path = "/api/apps",
    tag = "Apps",
    security(("bearer_auth" = [])),
    request_body = CreateAppRequest,
    responses(
        (status = 200, description = "App created", body = ApiResponse<AppDTO>),
        (status = 401, description = "Unauthorized"),
        (status = 409, description = "App code already exists"),
    )
)]
pub async fn create_app(
    State(state): State<AppState>,
    ValidatedJson(req): ValidatedJson<CreateAppRequest>,
) -> Result<Json<ApiResponse<AppDTO>>, AppError> {
    Ok(Json(ApiResponse::success(
        service::create_app(&state, &req).await?,
    )))
}

#[utoipa::path(
    get,
    path = "/api/apps",
    tag = "Apps",
    security(("bearer_auth" = [])),
    params(
        ("page" = Option<i64>, Query, description = "Page number (default: 1)"),
        ("page_size" = Option<i64>, Query, description = "Page size (default: 10)"),
    ),
    responses(
        (status = 200, description = "App list", body = ApiResponse<PageData<AppDTO>>),
        (status = 401, description = "Unauthorized"),
    )
)]
pub async fn list_apps(
    State(state): State<AppState>,
    Pagination { page, page_size }: Pagination,
) -> Result<Json<ApiResponse<PageData<AppDTO>>>, AppError> {
    Ok(Json(ApiResponse::success(
        service::list_apps(&state, page, page_size).await?,
    )))
}

#[utoipa::path(
    get,
    path = "/api/apps/{id}",
    tag = "Apps",
    security(("bearer_auth" = [])),
    params(
        ("id" = uuid::Uuid, Path, description = "App ID"),
    ),
    responses(
        (status = 200, description = "App details", body = ApiResponse<AppDTO>),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "App not found"),
    )
)]
pub async fn get_app(
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<ApiResponse<AppDTO>>, AppError> {
    Ok(Json(ApiResponse::success(
        service::get_app(&state, id).await?,
    )))
}

#[utoipa::path(
    put,
    path = "/api/apps/{id}",
    tag = "Apps",
    security(("bearer_auth" = [])),
    params(
        ("id" = uuid::Uuid, Path, description = "App ID"),
    ),
    request_body = UpdateAppRequest,
    responses(
        (status = 200, description = "App updated", body = ApiResponse<AppDTO>),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "App not found"),
    )
)]
pub async fn update_app(
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
    ValidatedJson(req): ValidatedJson<UpdateAppRequest>,
) -> Result<Json<ApiResponse<AppDTO>>, AppError> {
    Ok(Json(ApiResponse::success(
        service::update_app(&state, id, &req).await?,
    )))
}

#[utoipa::path(
    delete,
    path = "/api/apps/{id}",
    tag = "Apps",
    security(("bearer_auth" = [])),
    params(
        ("id" = uuid::Uuid, Path, description = "App ID"),
    ),
    responses(
        (status = 200, description = "App deleted", body = MessageResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "App not found"),
    )
)]
pub async fn delete_app(
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<MessageResponse>, AppError> {
    Ok(Json(service::delete_app(&state, id).await?))
}
