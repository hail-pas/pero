use axum::Json;
use axum::extract::{Path, State};

use crate::domains::oauth2::models::{
    CreateClientRequest, CreateClientResponse, OAuth2ClientDTO, UpdateClientRequest,
};
use crate::domains::oauth2::service;
use crate::shared::error::AppError;
use crate::shared::extractors::{Pagination, ValidatedJson};
use crate::shared::response::{ApiResponse, MessageResponse, PageData};
use crate::shared::state::AppState;

#[utoipa::path(
    post,
    path = "/api/oauth2/clients",
    tag = "OAuth2",
    security(("bearer_auth" = [])),
    request_body = crate::domains::oauth2::models::CreateClientRequest,
    responses(
        (status = 200, description = "Client created"),
        (status = 401, description = "Unauthorized"),
    )
)]
pub async fn create_client(
    State(state): State<AppState>,
    ValidatedJson(req): ValidatedJson<CreateClientRequest>,
) -> Result<Json<ApiResponse<CreateClientResponse>>, AppError> {
    let created = service::create_client(&state, &req).await?;

    Ok(Json(ApiResponse::success(CreateClientResponse {
        client: OAuth2ClientDTO::from(created.client),
        client_secret: created.client_secret,
    })))
}

#[utoipa::path(
    get,
    path = "/api/oauth2/clients",
    tag = "OAuth2",
    security(("bearer_auth" = [])),
    params(
        ("page" = Option<i64>, Query, description = "Page number (default: 1)"),
        ("page_size" = Option<i64>, Query, description = "Page size (default: 10)"),
    ),
    responses(
        (status = 200, description = "Client list"),
        (status = 401, description = "Unauthorized"),
    )
)]
pub async fn list_clients(
    State(state): State<AppState>,
    Pagination { page, page_size }: Pagination,
) -> Result<Json<ApiResponse<PageData<OAuth2ClientDTO>>>, AppError> {
    Ok(Json(ApiResponse::success(
        service::list_clients(&state, page, page_size).await?,
    )))
}

#[utoipa::path(
    get,
    path = "/api/oauth2/clients/{id}",
    tag = "OAuth2",
    security(("bearer_auth" = [])),
    params(
        ("id" = uuid::Uuid, Path, description = "Client ID"),
    ),
    responses(
        (status = 200, description = "Client details"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Client not found"),
    )
)]
pub async fn get_client(
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<ApiResponse<OAuth2ClientDTO>>, AppError> {
    Ok(Json(ApiResponse::success(
        service::get_client(&state, id).await?,
    )))
}

#[utoipa::path(
    put,
    path = "/api/oauth2/clients/{id}",
    tag = "OAuth2",
    security(("bearer_auth" = [])),
    params(
        ("id" = uuid::Uuid, Path, description = "Client ID"),
    ),
    request_body = crate::domains::oauth2::models::UpdateClientRequest,
    responses(
        (status = 200, description = "Client updated"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Client not found"),
    )
)]
pub async fn update_client(
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
    ValidatedJson(req): ValidatedJson<UpdateClientRequest>,
) -> Result<Json<ApiResponse<OAuth2ClientDTO>>, AppError> {
    Ok(Json(ApiResponse::success(
        service::update_client(&state, id, &req).await?,
    )))
}

#[utoipa::path(
    delete,
    path = "/api/oauth2/clients/{id}",
    tag = "OAuth2",
    security(("bearer_auth" = [])),
    params(
        ("id" = uuid::Uuid, Path, description = "Client ID"),
    ),
    responses(
        (status = 200, description = "Client deleted", body = MessageResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Client not found"),
    )
)]
pub async fn delete_client(
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<MessageResponse>, AppError> {
    service::delete_client(&state, id).await?;
    Ok(Json(MessageResponse::success("client deleted")))
}
