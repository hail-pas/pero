use crate::api::extractors::ValidatedJson;
use crate::api::response::{ApiResponse, MessageResponse};
use crate::domain::user::dto::{SetAttributes, UserAttribute};
use crate::domain::user::service;
use crate::shared::error::AppError;
use crate::shared::state::AppState;
use axum::Json;
use axum::extract::{Path, State};
#[utoipa::path(
    get,
    path = "/api/users/{id}/attributes",
    tag = "Identity",
    params(
        ("id" = uuid::Uuid, Path, description = "User ID"),
    ),
    responses(
        (status = 200, description = "User attributes", body = crate::api::response::ApiResponse<Vec<crate::api::schemas::user::UserAttributeDTO>>),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_attributes(
    State(state): State<AppState>,
    Path(user_id): Path<uuid::Uuid>,
) -> Result<Json<ApiResponse<Vec<UserAttribute>>>, AppError> {
    Ok(Json(ApiResponse::success(
        service::list_user_attributes(&*state.repos.users, &*state.repos.user_attributes, user_id)
            .await?,
    )))
}

#[utoipa::path(
    put,
    path = "/api/users/{id}/attributes",
    tag = "Identity",
    params(
        ("id" = uuid::Uuid, Path, description = "User ID"),
    ),
    responses(
        (status = 200, description = "Attributes updated", body = crate::api::response::MessageResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn set_attributes(
    State(state): State<AppState>,
    Path(user_id): Path<uuid::Uuid>,
    ValidatedJson(input): ValidatedJson<SetAttributes>,
) -> Result<Json<MessageResponse>, AppError> {
    service::set_user_attributes(
        &*state.repos.users,
        &*state.repos.user_attributes,
        &*state.repos.abac_cache,
        state.config.abac.policy_cache_ttl_seconds,
        user_id,
        &input,
    )
    .await?;
    Ok(Json(MessageResponse::success("attributes updated")))
}

#[utoipa::path(
    delete,
    path = "/api/users/{id}/attributes/{key}",
    tag = "Identity",
    params(
        ("id" = uuid::Uuid, Path, description = "User ID"),
        ("key" = String, Path, description = "Attribute key"),
    ),
    responses(
        (status = 200, description = "Attribute deleted", body = crate::api::response::MessageResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_attribute(
    State(state): State<AppState>,
    Path((user_id, key)): Path<(uuid::Uuid, String)>,
) -> Result<Json<MessageResponse>, AppError> {
    service::delete_user_attribute(
        &*state.repos.users,
        &*state.repos.user_attributes,
        &*state.repos.abac_cache,
        state.config.abac.policy_cache_ttl_seconds,
        user_id,
        &key,
    )
    .await?;
    Ok(Json(MessageResponse::success("attribute deleted")))
}
