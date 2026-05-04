use crate::api::extractors::{AuthUser, ValidatedJson};
use crate::api::response::{ApiResponse, MessageResponse};
use crate::domain::user::models::{BindRequest, Identity};
use crate::domain::user::service;
use crate::shared::error::AppError;
use crate::shared::state::AppState;
use axum::Json;
use axum::extract::{Path, State};
#[utoipa::path(
    get,
    path = "/api/identity/identities",
    tag = "Identity",
    responses(
        (status = 200, description = "Identity list", body = crate::api::response::ApiResponse<Vec<crate::api::schemas::user::IdentityDTO>>),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_identities(
    State(state): State<AppState>,
    auth_user: AuthUser,
) -> Result<Json<ApiResponse<Vec<Identity>>>, AppError> {
    Ok(Json(ApiResponse::success(
        service::list_identities(&*state.repos.identities, auth_user.user_id).await?,
    )))
}

pub async fn bind(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path(provider): Path<String>,
    ValidatedJson(req): ValidatedJson<BindRequest>,
) -> Result<Json<MessageResponse>, AppError> {
    service::bind_identity(&*state.repos.identities, auth_user.user_id, &provider, &req).await?;
    Ok(Json(MessageResponse::success("provider bound")))
}

#[utoipa::path(
    delete,
    path = "/api/identity/unbind/{provider}",
    tag = "Identity",
    params(
        ("provider" = String, Path, description = "Provider name"),
    ),
    responses(
        (status = 200, description = "Provider unbound", body = crate::api::response::MessageResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn unbind(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path(provider): Path<String>,
) -> Result<Json<MessageResponse>, AppError> {
    service::unbind_identity(&*state.repos.identities, auth_user.user_id, &provider).await?;
    Ok(Json(MessageResponse::success("provider unbound")))
}
