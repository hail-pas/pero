use axum::extract::{Path, State};
use axum::Json;

use crate::domains::app::models::{AppDTO, CreateAppRequest, UpdateAppRequest};
use crate::domains::app::repos::AppRepo;
use crate::shared::error::AppError;
use crate::shared::extractors::{Pagination, ValidatedJson};
use crate::shared::response::{ApiResponse, PageData};
use crate::shared::state::AppState;

pub async fn create_app(
    State(state): State<AppState>,
    ValidatedJson(req): ValidatedJson<CreateAppRequest>,
) -> Result<Json<ApiResponse<AppDTO>>, AppError> {
    if AppRepo::find_by_code(&state.db, &req.code)
        .await?
        .is_some()
    {
        return Err(AppError::Conflict(format!(
            "app code '{}' already exists",
            req.code
        )));
    }
    let app = AppRepo::create(&state.db, &req).await?;
    Ok(Json(ApiResponse::success(app.into())))
}

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

pub async fn get_app(
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<ApiResponse<AppDTO>>, AppError> {
    let app = AppRepo::find_by_id(&state.db, id)
        .await?
        .ok_or(AppError::NotFound("app".into()))?;
    Ok(Json(ApiResponse::success(app.into())))
}

pub async fn update_app(
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
    ValidatedJson(req): ValidatedJson<UpdateAppRequest>,
) -> Result<Json<ApiResponse<AppDTO>>, AppError> {
    let app = AppRepo::update(&state.db, id, &req).await?;
    Ok(Json(ApiResponse::success(app.into())))
}

pub async fn delete_app(
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<ApiResponse<()>>, AppError> {
    AppRepo::delete(&state.db, id).await?;
    Ok(Json(ApiResponse::<()>::success_message("app deleted")))
}
