use crate::domain::app::error;
use crate::domain::app::models::{AppDTO, CreateAppRequest, UpdateAppRequest};
use crate::domain::app::repo::AppStore;
use crate::shared::error::AppError;
use crate::shared::message::MessageResponse;
use crate::shared::page::PageData;

pub async fn create_app(store: &dyn AppStore, req: &CreateAppRequest) -> Result<AppDTO, AppError> {
    if store.find_by_code(&req.code).await?.is_some() {
        return Err(error::app_code_exists(&req.code));
    }

    Ok(store.create(req).await?.into())
}

pub async fn list_apps(
    store: &dyn AppStore,
    page: i64,
    page_size: i64,
) -> Result<PageData<AppDTO>, AppError> {
    let (apps, total) = store.list(page, page_size).await?;
    let items = apps.into_iter().map(AppDTO::from).collect();
    Ok(PageData::new(items, total, page, page_size))
}

pub async fn get_app(store: &dyn AppStore, id: uuid::Uuid) -> Result<AppDTO, AppError> {
    let app = store.find_by_id(id).await?.ok_or(error::app_not_found())?;
    Ok(app.into())
}

pub async fn update_app(
    store: &dyn AppStore,
    id: uuid::Uuid,
    req: &UpdateAppRequest,
) -> Result<AppDTO, AppError> {
    Ok(store.update(id, req).await?.into())
}

pub async fn delete_app(store: &dyn AppStore, id: uuid::Uuid) -> Result<MessageResponse, AppError> {
    store.delete(id).await?;
    Ok(MessageResponse::success("app deleted"))
}
