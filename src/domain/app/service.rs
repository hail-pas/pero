use crate::domain::app::error;
use crate::domain::app::models::{AppDTO, CreateAppRequest, UpdateAppRequest};
use crate::domain::app::store::AppRepo;
use crate::shared::error::AppError;
use crate::api::response::{MessageResponse, PageData};
use crate::shared::state::AppState;

pub async fn create_app(state: &AppState, req: &CreateAppRequest) -> Result<AppDTO, AppError> {
    if AppRepo::find_by_code(&state.db, &req.code).await?.is_some() {
        return Err(error::app_code_exists(&req.code));
    }

    Ok(AppRepo::create(&state.db, req).await?.into())
}

pub async fn list_apps(
    state: &AppState,
    page: i64,
    page_size: i64,
) -> Result<PageData<AppDTO>, AppError> {
    let (apps, total) = AppRepo::list(&state.db, page, page_size).await?;
    let items = apps.into_iter().map(AppDTO::from).collect();
    Ok(PageData::new(items, total, page, page_size))
}

pub async fn get_app(state: &AppState, id: uuid::Uuid) -> Result<AppDTO, AppError> {
    Ok(AppRepo::find_by_id_or_err(&state.db, id).await?.into())
}

pub async fn update_app(
    state: &AppState,
    id: uuid::Uuid,
    req: &UpdateAppRequest,
) -> Result<AppDTO, AppError> {
    Ok(AppRepo::update(&state.db, id, req).await?.into())
}

pub async fn delete_app(state: &AppState, id: uuid::Uuid) -> Result<MessageResponse, AppError> {
    AppRepo::delete(&state.db, id).await?;
    Ok(MessageResponse::success("app deleted"))
}
