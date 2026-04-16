use crate::domains::identity::models::{UpdateMeRequest, UpdateUserRequest, UserDTO};
use crate::domains::identity::repos::UserRepo;
use crate::cache::session;
use crate::shared::error::AppError;
use crate::shared::extractors::{AuthUser, Pagination, ValidatedJson};
use crate::shared::response::{ApiResponse, PageData};
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
    let user = UserRepo::find_by_id(&state.db, auth_user.user_id)
        .await?
        .ok_or(AppError::NotFound("user".into()))?;
    Ok(Json(ApiResponse::success(user.into())))
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
    let user = UserRepo::update_me(
        &state.db,
        auth_user.user_id,
        req.nickname.as_deref(),
        req.avatar_url.as_deref(),
        req.phone.as_deref(),
    )
    .await?;
    Ok(Json(ApiResponse::success(user.into())))
}

#[utoipa::path(
    get,
    path = "/api/users",
    tag = "Identity",
    security(("bearer_auth" = [])),
    params(
        ("page" = i64, Query, description = "Page number"),
        ("page_size" = i64, Query, description = "Page size"),
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
    let (users, total) = UserRepo::list(&state.db, page, page_size).await?;
    let items: Vec<UserDTO> = users.into_iter().map(UserDTO::from).collect();
    Ok(Json(ApiResponse::success(PageData::new(
        items, total, page, page_size,
    ))))
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
    let user = UserRepo::find_by_id(&state.db, id)
        .await?
        .ok_or(AppError::NotFound("user".into()))?;
    Ok(Json(ApiResponse::success(user.into())))
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
    crate::domains::identity::helpers::validate_update_user(
        &state.db,
        id,
        input.username.as_deref(),
        input.email.as_deref(),
    )
    .await?;

    let user = UserRepo::update(
        &state.db,
        id,
        input.username.as_deref(),
        input.email.as_deref(),
        input.phone.as_deref(),
        input.nickname.as_deref(),
        input.avatar_url.as_deref(),
        input.status,
    )
    .await?;
    Ok(Json(ApiResponse::success(user.into())))
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
        (status = 200, description = "User deleted", body = serde_json::Value),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "User not found"),
    )
)]
pub async fn delete_user(
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<ApiResponse<()>>, AppError> {
    session::revoke_refresh_token(&state.cache, &id.to_string()).await?;
    UserRepo::delete(&state.db, id).await?;
    Ok(Json(ApiResponse::<()>::success_message("user deleted")))
}
