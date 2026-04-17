use super::super::repos::UserRepo;
use super::super::repos::user_attr::{SetAttributes, UserAttribute, UserAttributeRepo};
use crate::shared::constants::cache_keys;
use crate::shared::error::AppError;
use crate::shared::extractors::ValidatedJson;
use crate::shared::response::ApiResponse;
use crate::shared::state::AppState;
use axum::Json;
use axum::extract::{Path, State};
use utoipa;

#[utoipa::path(
    get,
    path = "/api/users/{user_id}/attributes",
    tag = "Identity",
    security(("bearer_auth" = [])),
    params(
        ("user_id" = uuid::Uuid, Path, description = "User ID"),
    ),
    responses(
        (status = 200, description = "User attributes", body = ApiResponse<Vec<UserAttribute>>),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "User not found"),
    )
)]
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

#[utoipa::path(
    put,
    path = "/api/users/{user_id}/attributes",
    tag = "Identity",
    security(("bearer_auth" = [])),
    params(
        ("user_id" = uuid::Uuid, Path, description = "User ID"),
    ),
    request_body = SetAttributes,
    responses(
        (status = 200, description = "Attributes updated", body = serde_json::Value),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "User not found"),
    )
)]
pub async fn set_attributes(
    State(state): State<AppState>,
    Path(user_id): Path<uuid::Uuid>,
    ValidatedJson(input): ValidatedJson<SetAttributes>,
) -> Result<Json<ApiResponse<()>>, AppError> {
    UserRepo::find_by_id(&state.db, user_id)
        .await?
        .ok_or(AppError::NotFound("user".into()))?;

    UserAttributeRepo::upsert(&state.db, user_id, &input.attributes).await?;
    invalidate_user_abac_cache(&state, user_id).await?;
    Ok(Json(ApiResponse::<()>::success_message(
        "attributes updated",
    )))
}

#[utoipa::path(
    delete,
    path = "/api/users/{user_id}/attributes/{key}",
    tag = "Identity",
    security(("bearer_auth" = [])),
    params(
        ("user_id" = uuid::Uuid, Path, description = "User ID"),
        ("key" = String, Path, description = "Attribute key"),
    ),
    responses(
        (status = 200, description = "Attribute deleted", body = serde_json::Value),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "User not found"),
    )
)]
pub async fn delete_attribute(
    State(state): State<AppState>,
    Path((user_id, key)): Path<(uuid::Uuid, String)>,
) -> Result<Json<ApiResponse<()>>, AppError> {
    UserRepo::find_by_id(&state.db, user_id)
        .await?
        .ok_or(AppError::NotFound("user".into()))?;

    UserAttributeRepo::delete_by_user(&state.db, user_id, &key).await?;
    invalidate_user_abac_cache(&state, user_id).await?;
    Ok(Json(ApiResponse::<()>::success_message(
        "attribute deleted",
    )))
}

async fn invalidate_user_abac_cache(state: &AppState, user_id: uuid::Uuid) -> Result<(), AppError> {
    let pattern = format!("{}{}:*", cache_keys::ABAC_PREFIX, user_id);
    crate::cache::delete_by_pattern(&state.cache, &pattern).await
}
