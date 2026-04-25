use axum::Json;
use axum::extract::{Path, State};

use crate::api::extractors::ValidatedJson;
use crate::api::response::ApiResponse;
use crate::domain::social::entity::{
    CreateSocialProviderRequest, SocialProviderDTO, UpdateSocialProviderRequest,
};
use crate::domain::social::service;
use crate::shared::error::AppError;
use crate::shared::state::AppState;

pub async fn create_provider(
    State(state): State<AppState>,
    ValidatedJson(req): ValidatedJson<CreateSocialProviderRequest>,
) -> Result<Json<ApiResponse<SocialProviderDTO>>, AppError> {
    let provider = service::create_provider(&state, &req).await?;
    Ok(Json(ApiResponse::success(provider.into())))
}

pub async fn list_providers(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<Vec<SocialProviderDTO>>>, AppError> {
    let providers = service::list_providers(&state).await?;
    let items: Vec<SocialProviderDTO> = providers.into_iter().map(Into::into).collect();
    Ok(Json(ApiResponse::success(items)))
}

pub async fn get_provider(
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<ApiResponse<SocialProviderDTO>>, AppError> {
    let provider = service::get_provider(&state, id).await?;
    Ok(Json(ApiResponse::success(provider.into())))
}

pub async fn update_provider(
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
    ValidatedJson(req): ValidatedJson<UpdateSocialProviderRequest>,
) -> Result<Json<ApiResponse<SocialProviderDTO>>, AppError> {
    let provider = service::update_provider(&state, id, &req).await?;
    Ok(Json(ApiResponse::success(provider.into())))
}

pub async fn delete_provider(
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<ApiResponse<()>>, AppError> {
    service::delete_provider(&state, id).await?;
    Ok(Json(ApiResponse::success(())))
}
