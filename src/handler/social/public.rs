use axum::Json;
use axum::extract::State;

use crate::api::response::ApiResponse;
use crate::domain::social::entity::SocialProviderPublic;
use crate::domain::social::service;
use crate::shared::error::AppError;
use crate::shared::state::AppState;

pub async fn list_enabled_providers(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<Vec<SocialProviderPublic>>>, AppError> {
    let providers = service::list_enabled_providers(&state).await?;
    Ok(Json(ApiResponse::success(providers)))
}
