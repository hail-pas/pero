use axum::extract::{Path, State};
use axum::Json;
use crate::domains::identity::models::{UserDTO, UpdateUserRequest, UpdateMeRequest};
use crate::domains::identity::repos::UserRepo;
use crate::shared::error::AppError;
use crate::shared::extractors::{AuthUser, ValidatedJson, Pagination};
use crate::shared::response::{ApiResponse, PageData};
use crate::shared::state::AppState;

pub async fn get_me(
    State(state): State<AppState>,
    auth_user: AuthUser,
) -> Result<Json<ApiResponse<UserDTO>>, AppError> {
    let user = UserRepo::find_by_id(&state.db, auth_user.user_id)
        .await?
        .ok_or(AppError::NotFound("user".into()))?;
    Ok(Json(ApiResponse::success(user.into())))
}

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

pub async fn list_users(
    State(state): State<AppState>,
    Pagination { page, page_size }: Pagination,
) -> Result<Json<ApiResponse<PageData<UserDTO>>>, AppError> {
    let (users, total) = UserRepo::list(&state.db, page, page_size).await?;
    let items: Vec<UserDTO> = users.into_iter().map(UserDTO::from).collect();
    Ok(Json(ApiResponse::success(PageData::new(items, total, page, page_size))))
}

pub async fn get_user(
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<ApiResponse<UserDTO>>, AppError> {
    let user = UserRepo::find_by_id(&state.db, id)
        .await?
        .ok_or(AppError::NotFound("user".into()))?;
    Ok(Json(ApiResponse::success(user.into())))
}

pub async fn update_user(
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
    ValidatedJson(input): ValidatedJson<UpdateUserRequest>,
) -> Result<Json<ApiResponse<UserDTO>>, AppError> {
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

pub async fn delete_user(
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<ApiResponse<()>>, AppError> {
    UserRepo::delete(&state.db, id).await?;
    Ok(Json(ApiResponse::<()>::success_message("user deleted")))
}
