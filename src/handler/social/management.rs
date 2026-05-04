use axum::Json;
use axum::extract::{Path, State};

use crate::api::extractors::ValidatedJson;
use crate::api::response::ApiResponse;
use crate::domain::federation::entity::{
    CreateSocialProviderRequest, SocialProviderDTO, UpdateSocialProviderRequest,
};
use crate::domain::federation::service;
use crate::shared::error::AppError;
use crate::shared::state::AppState;

#[utoipa::path(
    post,
    path = "/api/social-providers",
    tag = "Social",
    request_body = crate::api::schemas::social::CreateSocialProviderRequest,
    responses(
        (status = 200, description = "Provider created", body = crate::api::response::ApiResponse<crate::api::schemas::social::SocialProviderDTO>),
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_provider(
    State(state): State<AppState>,
    ValidatedJson(req): ValidatedJson<CreateSocialProviderRequest>,
) -> Result<Json<ApiResponse<SocialProviderDTO>>, AppError> {
    let provider = service::create_provider(&*state.repos.social, &req).await?;
    Ok(Json(ApiResponse::success(provider.into())))
}

#[utoipa::path(
    get,
    path = "/api/social-providers",
    tag = "Social",
    responses(
        (status = 200, description = "Provider list", body = crate::api::response::ApiResponse<Vec<crate::api::schemas::social::SocialProviderDTO>>),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_providers(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<Vec<SocialProviderDTO>>>, AppError> {
    let providers = service::list_providers(&*state.repos.social).await?;
    let items: Vec<SocialProviderDTO> = providers.into_iter().map(Into::into).collect();
    Ok(Json(ApiResponse::success(items)))
}

#[utoipa::path(
    get,
    path = "/api/social-providers/{id}",
    tag = "Social",
    params(
        ("id" = uuid::Uuid, Path, description = "Provider ID"),
    ),
    responses(
        (status = 200, description = "Provider detail", body = crate::api::response::ApiResponse<crate::api::schemas::social::SocialProviderDTO>),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_provider(
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<ApiResponse<SocialProviderDTO>>, AppError> {
    let provider = service::get_provider(&*state.repos.social, id).await?;
    Ok(Json(ApiResponse::success(provider.into())))
}

#[utoipa::path(
    put,
    path = "/api/social-providers/{id}",
    tag = "Social",
    params(
        ("id" = uuid::Uuid, Path, description = "Provider ID"),
    ),
    request_body = crate::api::schemas::social::UpdateSocialProviderRequest,
    responses(
        (status = 200, description = "Provider updated", body = crate::api::response::ApiResponse<crate::api::schemas::social::SocialProviderDTO>),
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_provider(
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
    ValidatedJson(req): ValidatedJson<UpdateSocialProviderRequest>,
) -> Result<Json<ApiResponse<SocialProviderDTO>>, AppError> {
    let provider = service::update_provider(&*state.repos.social, id, &req).await?;
    Ok(Json(ApiResponse::success(provider.into())))
}

#[utoipa::path(
    delete,
    path = "/api/social-providers/{id}",
    tag = "Social",
    params(
        ("id" = uuid::Uuid, Path, description = "Provider ID"),
    ),
    responses(
        (status = 200, description = "Provider deleted", body = crate::api::response::MessageResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_provider(
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<crate::api::response::MessageResponse>, AppError> {
    service::delete_provider(&*state.repos.social, id).await?;
    Ok(Json(crate::api::response::MessageResponse::success(
        "provider deleted",
    )))
}
