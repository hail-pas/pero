use axum::Json;
use axum::extract::{Path, State};

use crate::domains::app::models::{AppDTO, CreateAppRequest, UpdateAppRequest};
use crate::domains::app::repos::AppRepo;
use crate::shared::error::AppError;
use crate::shared::extractors::{Pagination, ValidatedJson};
use crate::shared::response::{ApiResponse, PageData};
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
    if AppRepo::find_by_code(&state.db, &req.code).await?.is_some() {
        return Err(AppError::Conflict(format!(
            "app code '{}' already exists",
            req.code
        )));
    }
    let app = AppRepo::create(&state.db, &req).await?;
    Ok(Json(ApiResponse::success(app.into())))
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
    let (apps, total) = AppRepo::list(&state.db, page, page_size).await?;
    let items: Vec<AppDTO> = apps.into_iter().map(AppDTO::from).collect();
    Ok(Json(ApiResponse::success(PageData::new(
        items, total, page, page_size,
    ))))
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
    let app = AppRepo::find_by_id_or_err(&state.db, id).await?;
    Ok(Json(ApiResponse::success(app.into())))
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
    let app = AppRepo::update(&state.db, id, &req).await?;
    Ok(Json(ApiResponse::success(app.into())))
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
        (status = 200, description = "App deleted", body = serde_json::Value),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "App not found"),
    )
)]
pub async fn delete_app(
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<ApiResponse<()>>, AppError> {
    AppRepo::delete(&state.db, id).await?;
    Ok(Json(ApiResponse::<()>::success_message("app deleted")))
}
