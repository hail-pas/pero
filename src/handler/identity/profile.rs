use crate::api::extractors::{AuthUser, Pagination, ValidatedJson};
use crate::api::response::{ApiResponse, MessageResponse, PageData};
use crate::domain::identity::models::{UpdateMeRequest, UpdateUserRequest, UserDTO};
use crate::domain::identity::service;
use crate::shared::error::AppError;
use crate::shared::state::AppState;
use axum::Json;
use axum::extract::{Path, State};
use utoipa;

#[utoipa::path(
    get,
    path = "/api/users/me",
    tag = "Identity",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Current user profile", body = ApiResponse<UserDTO>),
        (status = 401, description = "Unauthorized"),
    )
)]
pub async fn get_me(
    State(state): State<AppState>,
    auth_user: AuthUser,
) -> Result<Json<ApiResponse<UserDTO>>, AppError> {
    Ok(Json(ApiResponse::success(
        service::get_me(&*state.repos.users, auth_user.user_id).await?,
    )))
}

#[utoipa::path(
    put,
    path = "/api/users/me",
    tag = "Identity",
    security(("bearer_auth" = [])),
    request_body = UpdateMeRequest,
    responses(
        (status = 200, description = "Profile updated", body = ApiResponse<UserDTO>),
        (status = 401, description = "Unauthorized"),
    )
)]
pub async fn update_me(
    State(state): State<AppState>,
    auth_user: AuthUser,
    ValidatedJson(req): ValidatedJson<UpdateMeRequest>,
) -> Result<Json<ApiResponse<UserDTO>>, AppError> {
    Ok(Json(ApiResponse::success(
        service::update_me(&*state.repos.users, auth_user.user_id, &req).await?,
    )))
}

#[utoipa::path(
    get,
    path = "/api/users",
    tag = "Identity",
    security(("bearer_auth" = [])),
    params(
        ("page" = Option<i64>, Query, description = "Page number (default: 1)"),
        ("page_size" = Option<i64>, Query, description = "Page size (default: 10)"),
    ),
    responses(
        (status = 200, description = "User list", body = ApiResponse<PageData<UserDTO>>),
        (status = 401, description = "Unauthorized"),
    )
)]
pub async fn list_users(
    State(state): State<AppState>,
    Pagination { page, page_size }: Pagination,
) -> Result<Json<ApiResponse<PageData<UserDTO>>>, AppError> {
    Ok(Json(ApiResponse::success(
        service::list_users(&*state.repos.users, page, page_size).await?,
    )))
}

#[utoipa::path(
    get,
    path = "/api/users/{id}",
    tag = "Identity",
    security(("bearer_auth" = [])),
    params(
        ("id" = uuid::Uuid, Path, description = "User ID"),
    ),
    responses(
        (status = 200, description = "User details", body = ApiResponse<UserDTO>),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "User not found"),
    )
)]
pub async fn get_user(
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<ApiResponse<UserDTO>>, AppError> {
    Ok(Json(ApiResponse::success(
        service::get_user(&*state.repos.users, id).await?,
    )))
}

#[utoipa::path(
    put,
    path = "/api/users/{id}",
    tag = "Identity",
    security(("bearer_auth" = [])),
    params(
        ("id" = uuid::Uuid, Path, description = "User ID"),
    ),
    request_body = UpdateUserRequest,
    responses(
        (status = 200, description = "User updated", body = ApiResponse<UserDTO>),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "User not found"),
    )
)]
pub async fn update_user(
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
    ValidatedJson(input): ValidatedJson<UpdateUserRequest>,
) -> Result<Json<ApiResponse<UserDTO>>, AppError> {
    Ok(Json(ApiResponse::success(
        service::update_user(
            &*state.repos.users,
            &*state.repos.sessions,
            &*state.repos.oauth2_tokens,
            id,
            &input,
        ).await?,
    )))
}

#[utoipa::path(
    delete,
    path = "/api/users/{id}",
    tag = "Identity",
    security(("bearer_auth" = [])),
    params(
        ("id" = uuid::Uuid, Path, description = "User ID"),
    ),
    responses(
        (status = 200, description = "User deleted", body = MessageResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "User not found"),
    )
)]
pub async fn delete_user(
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<MessageResponse>, AppError> {
    Ok(Json(service::delete_user(
        &*state.repos.users,
        &*state.repos.sessions,
        &*state.repos.oauth2_tokens,
        id,
    ).await?))
}
