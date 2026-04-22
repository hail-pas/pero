use crate::domains::identity::models::{BindRequest, Identity};
use crate::domains::identity::service;
use crate::shared::error::AppError;
use crate::shared::extractors::{AuthUser, ValidatedJson};
use crate::shared::response::{ApiResponse, MessageResponse};
use crate::shared::state::AppState;
use axum::Json;
use axum::extract::{Path, State};
use utoipa;

#[utoipa::path(
    get,
    path = "/api/identity/identities",
    tag = "Identity",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "User identities", body = ApiResponse<Vec<Identity>>),
        (status = 401, description = "Unauthorized"),
    )
)]
pub async fn list_identities(
    State(state): State<AppState>,
    auth_user: AuthUser,
) -> Result<Json<ApiResponse<Vec<Identity>>>, AppError> {
    Ok(Json(ApiResponse::success(
        service::list_identities(&state, auth_user.user_id).await?,
    )))
}

#[utoipa::path(
    post,
    path = "/api/identity/bind/{provider}",
    tag = "Identity",
    security(("bearer_auth" = [])),
    params(
        ("provider" = String, Path, description = "OAuth provider name"),
    ),
    request_body = BindRequest,
    responses(
        (status = 200, description = "Provider bound", body = MessageResponse),
        (status = 400, description = "Provider not yet implemented"),
        (status = 401, description = "Unauthorized"),
        (status = 409, description = "Provider already bound"),
    )
)]
pub async fn bind(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path(provider): Path<String>,
    ValidatedJson(req): ValidatedJson<BindRequest>,
) -> Result<Json<MessageResponse>, AppError> {
    Ok(Json(
        service::bind_identity(&state, auth_user.user_id, &provider, &req).await?,
    ))
}

#[utoipa::path(
    delete,
    path = "/api/identity/unbind/{provider}",
    tag = "Identity",
    security(("bearer_auth" = [])),
    params(
        ("provider" = String, Path, description = "OAuth provider name"),
    ),
    responses(
        (status = 200, description = "Provider unbound", body = MessageResponse),
        (status = 400, description = "Cannot unbind password / must keep one method"),
        (status = 401, description = "Unauthorized"),
    )
)]
pub async fn unbind(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path(provider): Path<String>,
) -> Result<Json<MessageResponse>, AppError> {
    Ok(Json(
        service::unbind_identity(&state, auth_user.user_id, &provider).await?,
    ))
}
