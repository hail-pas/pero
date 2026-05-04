use axum::Json;
use axum::extract::State;

use crate::api::response::ApiResponse;
use crate::domain::federation::entity::SocialProviderPublic;
use crate::domain::federation::service;
use crate::shared::error::AppError;
use crate::shared::state::AppState;

#[utoipa::path(
    get,
    path = "/api/social-providers/enabled",
    tag = "Social",
    responses(
        (status = 200, description = "Enabled providers", body = crate::api::response::ApiResponse<Vec<crate::api::schemas::social::SocialProviderPublicDTO>>),
    )
)]
pub async fn list_enabled_providers(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<Vec<SocialProviderPublic>>>, AppError> {
    let providers = service::list_enabled_providers(&*state.repos.social).await?;
    Ok(Json(ApiResponse::success(providers)))
}
