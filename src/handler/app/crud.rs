use axum::Json;
use axum::extract::{Path, State};

use crate::api::extractors::{Pagination, ValidatedJson};
use crate::api::response::{ApiResponse, MessageResponse, PageData};
use crate::domain::app::models::{AppDTO, CreateAppRequest, UpdateAppRequest};
use crate::domain::app::service;
use crate::shared::error::AppError;
use crate::shared::state::AppState;

#[utoipa::path(
    post,
    path = "/api/apps",
    tag = "Apps",
    request_body = crate::api::schemas::app::CreateAppRequest,
    responses(
        (status = 200, description = "App created", body = crate::api::response::ApiResponse<crate::api::schemas::app::AppDTO>),
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_app(
    State(state): State<AppState>,
    ValidatedJson(req): ValidatedJson<CreateAppRequest>,
) -> Result<Json<ApiResponse<AppDTO>>, AppError> {
    Ok(Json(ApiResponse::success(
        service::create_app(&*state.repos.apps, &req).await?,
    )))
}

#[utoipa::path(
    get,
    path = "/api/apps",
    tag = "Apps",
    params(
        ("page" = Option<i64>, Query, description = "Page number"),
        ("page_size" = Option<i64>, Query, description = "Page size"),
    ),
    responses(
        (status = 200, description = "App list", body = crate::api::response::ApiResponse<crate::api::response::PageData<crate::api::schemas::app::AppDTO>>),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_apps(
    State(state): State<AppState>,
    Pagination { page, page_size }: Pagination,
) -> Result<Json<ApiResponse<PageData<AppDTO>>>, AppError> {
    let (items, total) = service::list_apps(&*state.repos.apps, page, page_size).await?;
    Ok(Json(ApiResponse::success(PageData::new(
        items, total, page, page_size,
    ))))
}

#[utoipa::path(
    get,
    path = "/api/apps/{id}",
    tag = "Apps",
    params(
        ("id" = uuid::Uuid, Path, description = "App ID"),
    ),
    responses(
        (status = 200, description = "App detail", body = crate::api::response::ApiResponse<crate::api::schemas::app::AppDTO>),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_app(
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<ApiResponse<AppDTO>>, AppError> {
    Ok(Json(ApiResponse::success(
        service::get_app(&*state.repos.apps, id).await?,
    )))
}

#[utoipa::path(
    put,
    path = "/api/apps/{id}",
    tag = "Apps",
    params(
        ("id" = uuid::Uuid, Path, description = "App ID"),
    ),
    request_body = crate::api::schemas::app::UpdateAppRequest,
    responses(
        (status = 200, description = "App updated", body = crate::api::response::ApiResponse<crate::api::schemas::app::AppDTO>),
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_app(
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
    ValidatedJson(req): ValidatedJson<UpdateAppRequest>,
) -> Result<Json<ApiResponse<AppDTO>>, AppError> {
    Ok(Json(ApiResponse::success(
        service::update_app(&*state.repos.apps, id, &req).await?,
    )))
}

#[utoipa::path(
    delete,
    path = "/api/apps/{id}",
    tag = "Apps",
    params(
        ("id" = uuid::Uuid, Path, description = "App ID"),
    ),
    responses(
        (status = 200, description = "App deleted", body = crate::api::response::MessageResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_app(
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<MessageResponse>, AppError> {
    service::delete_app(&*state.repos.apps, id).await?;
    Ok(Json(MessageResponse::success("app deleted")))
}
