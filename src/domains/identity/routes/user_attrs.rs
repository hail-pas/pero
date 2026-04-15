use axum::extract::{Path, State};
use axum::Json;
use super::super::repos::user_attr::{UserAttributeRepo, SetAttributes, UserAttribute};
use super::super::repos::UserRepo;
use crate::shared::error::AppError;
use crate::shared::response::ApiResponse;
use crate::shared::state::AppState;

pub async fn list_attributes(
    State(state): State<AppState>,
    Path(user_id): Path<uuid::Uuid>,
) -> Result<Json<ApiResponse<Vec<UserAttribute>>>, AppError> {
    UserRepo::find_by_id(&state.db, user_id)
        .await?
        .ok_or(AppError::NotFound("user".into()))?;

    let attrs = UserAttributeRepo::list_by_user(&state.db, user_id).await?;
    Ok(Json(ApiResponse::success(attrs)))
}

pub async fn set_attributes(
    State(state): State<AppState>,
    Path(user_id): Path<uuid::Uuid>,
    Json(input): Json<SetAttributes>,
) -> Result<Json<ApiResponse<()>>, AppError> {
    UserRepo::find_by_id(&state.db, user_id)
        .await?
        .ok_or(AppError::NotFound("user".into()))?;

    UserAttributeRepo::upsert(&state.db, user_id, &input.attributes).await?;
    Ok(Json(ApiResponse::<()>::success_message("attributes updated")))
}
