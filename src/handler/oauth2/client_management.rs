use axum::Json;
use axum::extract::{Path, State};

use crate::api::extractors::{Pagination, ValidatedJson};
use crate::api::response::{ApiResponse, MessageResponse, PageData};
use crate::domain::oauth::models::{
    CreateClientRequest, CreateClientResponse, OAuth2ClientDTO, UpdateClientRequest,
};
use crate::domain::oauth::service;
use crate::shared::error::AppError;
use crate::shared::state::AppState;

#[utoipa::path(
    post,
    path = "/api/oauth2/clients",
    tag = "OAuth2",
    request_body = crate::api::schemas::oauth::CreateClientRequest,
    responses(
        (status = 200, description = "Client created", body = crate::api::response::ApiResponse<crate::api::schemas::oauth::CreateClientResponse>),
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_client(
    State(state): State<AppState>,
    ValidatedJson(req): ValidatedJson<CreateClientRequest>,
) -> Result<Json<ApiResponse<CreateClientResponse>>, AppError> {
    let created =
        service::create_client(&*state.repos.apps, &*state.repos.oauth2_clients, &req).await?;

    Ok(Json(ApiResponse::success(CreateClientResponse {
        client: OAuth2ClientDTO::from(created.client),
        client_secret: created.client_secret,
    })))
}

#[utoipa::path(
    get,
    path = "/api/oauth2/clients",
    tag = "OAuth2",
    params(
        ("page" = Option<i64>, Query, description = "Page number"),
        ("page_size" = Option<i64>, Query, description = "Page size"),
    ),
    responses(
        (status = 200, description = "Client list", body = crate::api::response::ApiResponse<crate::api::response::PageData<crate::api::schemas::oauth::OAuth2ClientDTO>>),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_clients(
    State(state): State<AppState>,
    Pagination { page, page_size }: Pagination,
) -> Result<Json<ApiResponse<PageData<OAuth2ClientDTO>>>, AppError> {
    let (items, total) =
        service::list_clients(&*state.repos.oauth2_clients, page, page_size).await?;
    Ok(Json(ApiResponse::success(PageData::new(
        items, total, page, page_size,
    ))))
}

#[utoipa::path(
    get,
    path = "/api/oauth2/clients/{id}",
    tag = "OAuth2",
    params(
        ("id" = uuid::Uuid, Path, description = "Client ID"),
    ),
    responses(
        (status = 200, description = "Client detail", body = crate::api::response::ApiResponse<crate::api::schemas::oauth::OAuth2ClientDTO>),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_client(
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<ApiResponse<OAuth2ClientDTO>>, AppError> {
    Ok(Json(ApiResponse::success(
        service::get_client(&*state.repos.oauth2_clients, id).await?,
    )))
}

#[utoipa::path(
    put,
    path = "/api/oauth2/clients/{id}",
    tag = "OAuth2",
    params(
        ("id" = uuid::Uuid, Path, description = "Client ID"),
    ),
    request_body = crate::api::schemas::oauth::UpdateClientRequest,
    responses(
        (status = 200, description = "Client updated", body = crate::api::response::ApiResponse<crate::api::schemas::oauth::OAuth2ClientDTO>),
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_client(
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
    ValidatedJson(req): ValidatedJson<UpdateClientRequest>,
) -> Result<Json<ApiResponse<OAuth2ClientDTO>>, AppError> {
    Ok(Json(ApiResponse::success(
        service::update_client(&*state.repos.oauth2_clients, id, &req).await?,
    )))
}

#[utoipa::path(
    delete,
    path = "/api/oauth2/clients/{id}",
    tag = "OAuth2",
    params(
        ("id" = uuid::Uuid, Path, description = "Client ID"),
    ),
    responses(
        (status = 200, description = "Client deleted", body = crate::api::response::MessageResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_client(
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<MessageResponse>, AppError> {
    service::delete_client(&*state.repos.oauth2_clients, id).await?;
    Ok(Json(MessageResponse::success("client deleted")))
}
