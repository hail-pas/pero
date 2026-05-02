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

#[utoipa::path(
    post,
    path = "/api/social-providers",
    tag = "Social",
    security(("bearer_auth" = [])),
    request_body = CreateSocialProviderRequest,
    responses(
        (status = 200, description = "Provider created", body = ApiResponse<SocialProviderDTO>),
        (status = 401, description = "Unauthorized"),
    )
)]
pub async fn create_provider(
    State(state): State<AppState>,
    ValidatedJson(req): ValidatedJson<CreateSocialProviderRequest>,
) -> Result<Json<ApiResponse<SocialProviderDTO>>, AppError> {
    let provider = service::create_provider(&state, &req).await?;
    Ok(Json(ApiResponse::success(provider.into())))
}

#[utoipa::path(
    get,
    path = "/api/social-providers",
    tag = "Social",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Provider list", body = ApiResponse<Vec<SocialProviderDTO>>),
        (status = 401, description = "Unauthorized"),
    )
)]
pub async fn list_providers(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<Vec<SocialProviderDTO>>>, AppError> {
    let providers = service::list_providers(&state).await?;
    let items: Vec<SocialProviderDTO> = providers.into_iter().map(Into::into).collect();
    Ok(Json(ApiResponse::success(items)))
}

#[utoipa::path(
    get,
    path = "/api/social-providers/{id}",
    tag = "Social",
    security(("bearer_auth" = [])),
    params(
        ("id" = uuid::Uuid, Path, description = "Provider ID"),
    ),
    responses(
        (status = 200, description = "Provider details", body = ApiResponse<SocialProviderDTO>),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Provider not found"),
    )
)]
pub async fn get_provider(
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<ApiResponse<SocialProviderDTO>>, AppError> {
    let provider = service::get_provider(&state, id).await?;
    Ok(Json(ApiResponse::success(provider.into())))
}

#[utoipa::path(
    put,
    path = "/api/social-providers/{id}",
    tag = "Social",
    security(("bearer_auth" = [])),
    params(
        ("id" = uuid::Uuid, Path, description = "Provider ID"),
    ),
    request_body = UpdateSocialProviderRequest,
    responses(
        (status = 200, description = "Provider updated", body = ApiResponse<SocialProviderDTO>),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Provider not found"),
    )
)]
pub async fn update_provider(
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
    ValidatedJson(req): ValidatedJson<UpdateSocialProviderRequest>,
) -> Result<Json<ApiResponse<SocialProviderDTO>>, AppError> {
    let provider = service::update_provider(&state, id, &req).await?;
    Ok(Json(ApiResponse::success(provider.into())))
}

#[utoipa::path(
    delete,
    path = "/api/social-providers/{id}",
    tag = "Social",
    security(("bearer_auth" = [])),
    params(
        ("id" = uuid::Uuid, Path, description = "Provider ID"),
    ),
    responses(
        (status = 200, description = "Provider deleted", body = crate::api::response::MessageResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Provider not found"),
    )
)]
pub async fn delete_provider(
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<crate::api::response::MessageResponse>, AppError> {
    service::delete_provider(&state, id).await?;
    Ok(Json(crate::api::response::MessageResponse::success(
        "provider deleted",
    )))
}
