use crate::api::extractors::{AuthUser, Pagination, ValidatedJson};
use crate::api::response::{ApiResponse, MessageResponse, PageData};
use crate::domain::user::models::{UpdateMeRequest, UpdateUserRequest, UserDTO};
use crate::domain::user::service;
use crate::shared::error::AppError;
use crate::shared::state::AppState;
use axum::Json;
use axum::extract::{Path, State};
#[utoipa::path(
    get,
    path = "/api/users/me",
    tag = "Identity",
    responses(
        (status = 200, description = "Current user profile", body = crate::api::response::ApiResponse<crate::api::schemas::user::UserDTO>),
    ),
    security(("bearer_auth" = []))
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
    request_body = crate::api::schemas::user::UpdateMeRequest,
    responses(
        (status = 200, description = "Profile updated", body = crate::api::response::ApiResponse<crate::api::schemas::user::UserDTO>),
    ),
    security(("bearer_auth" = []))
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
    params(
        ("page" = Option<i64>, Query, description = "Page number"),
        ("page_size" = Option<i64>, Query, description = "Page size"),
    ),
    responses(
        (status = 200, description = "User list", body = crate::api::response::ApiResponse<crate::api::response::PageData<crate::api::schemas::user::UserDTO>>),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_users(
    State(state): State<AppState>,
    Pagination { page, page_size }: Pagination,
) -> Result<Json<ApiResponse<PageData<UserDTO>>>, AppError> {
    let (items, total) = service::list_users(&*state.repos.users, page, page_size).await?;
    Ok(Json(ApiResponse::success(PageData::new(
        items, total, page, page_size,
    ))))
}

#[utoipa::path(
    get,
    path = "/api/users/{id}",
    tag = "Identity",
    params(
        ("id" = uuid::Uuid, Path, description = "User ID"),
    ),
    responses(
        (status = 200, description = "User detail", body = crate::api::response::ApiResponse<crate::api::schemas::user::UserDTO>),
    ),
    security(("bearer_auth" = []))
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
    params(
        ("id" = uuid::Uuid, Path, description = "User ID"),
    ),
    request_body = crate::api::schemas::user::UpdateUserRequest,
    responses(
        (status = 200, description = "User updated", body = crate::api::response::ApiResponse<crate::api::schemas::user::UserDTO>),
    ),
    security(("bearer_auth" = []))
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
            &*state.repos.refresh_tokens,
            id,
            &input,
        )
        .await?,
    )))
}

#[utoipa::path(
    delete,
    path = "/api/users/{id}",
    tag = "Identity",
    params(
        ("id" = uuid::Uuid, Path, description = "User ID"),
    ),
    responses(
        (status = 200, description = "User deleted", body = crate::api::response::MessageResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_user(
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<MessageResponse>, AppError> {
    service::delete_user(
        &*state.repos.users,
        &*state.repos.sessions,
        &*state.repos.refresh_tokens,
        id,
    )
    .await?;
    Ok(Json(MessageResponse::success("user deleted")))
}
