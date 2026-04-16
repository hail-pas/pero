use axum::Json;
use axum::extract::{Path, State};

use crate::domains::oauth2::models::{CreateClientRequest, OAuth2ClientDTO, UpdateClientRequest};
use crate::domains::oauth2::repos::OAuth2ClientRepo;
use crate::shared::error::AppError;
use crate::shared::extractors::{Pagination, ValidatedJson};
use crate::shared::response::{ApiResponse, PageData};
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
) -> Result<Json<ApiResponse<serde_json::Value>>, AppError> {
    let client_id = uuid::Uuid::new_v4().to_string().replace('-', "");
    let client_secret = uuid::Uuid::new_v4().to_string().replace('-', "");
    let client_secret_hash = crate::domains::identity::helpers::hash_password(&client_secret)?;

    let client = OAuth2ClientRepo::create(&state.db, &client_id, &client_secret_hash, &req).await?;

    Ok(Json(ApiResponse::success(serde_json::json!({
        "client": OAuth2ClientDTO::from(client),
        "client_secret": client_secret,
    }))))
}

#[utoipa::path(
    get,
    path = "/api/oauth2/clients",
    tag = "OAuth2",
    security(("bearer_auth" = [])),
    params(
        ("page" = i64, Query, description = "Page number"),
        ("page_size" = i64, Query, description = "Page size"),
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
    let (clients, total) = OAuth2ClientRepo::list(&state.db, page, page_size).await?;
    let items: Vec<OAuth2ClientDTO> = clients.into_iter().map(OAuth2ClientDTO::from).collect();
    Ok(Json(ApiResponse::success(PageData::new(
        items, total, page, page_size,
    ))))
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
    let client = OAuth2ClientRepo::find_by_id(&state.db, id)
        .await?
        .ok_or(AppError::NotFound("oauth2 client".into()))?;
    Ok(Json(ApiResponse::success(client.into())))
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
    let client = OAuth2ClientRepo::update(&state.db, id, &req).await?;
    Ok(Json(ApiResponse::success(client.into())))
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
        (status = 200, description = "Client deleted", body = serde_json::Value),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Client not found"),
    )
)]
pub async fn delete_client(
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<ApiResponse<()>>, AppError> {
    OAuth2ClientRepo::delete(&state.db, id).await?;
    Ok(Json(ApiResponse::<()>::success_message("client deleted")))
}
