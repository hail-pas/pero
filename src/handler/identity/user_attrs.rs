use crate::api::extractors::ValidatedJson;
use crate::api::response::{ApiResponse, MessageResponse};
use crate::domain::identity::service;
use crate::domain::identity::store::{SetAttributes, UserAttribute};
use crate::shared::error::AppError;
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
    Ok(Json(ApiResponse::success(
        service::list_user_attributes(&state, user_id).await?,
    )))
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
        (status = 200, description = "Attributes updated", body = MessageResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "User not found"),
    )
)]
pub async fn set_attributes(
    State(state): State<AppState>,
    Path(user_id): Path<uuid::Uuid>,
    ValidatedJson(input): ValidatedJson<SetAttributes>,
) -> Result<Json<MessageResponse>, AppError> {
    Ok(Json(
        service::set_user_attributes(&state, user_id, &input).await?,
    ))
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
        (status = 200, description = "Attribute deleted", body = MessageResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "User not found"),
    )
)]
pub async fn delete_attribute(
    State(state): State<AppState>,
    Path((user_id, key)): Path<(uuid::Uuid, String)>,
) -> Result<Json<MessageResponse>, AppError> {
    Ok(Json(
        service::delete_user_attribute(&state, user_id, &key).await?,
    ))
}
