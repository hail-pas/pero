use axum::extract::{Path, State};
use axum::Json;
use crate::db::repos::{UserRepo, UserDTO, CreateUser, UpdateUser};
use crate::error::AppError;
use crate::extractors::{ValidatedJson, Pagination};
use crate::response::{ApiResponse, PageData};
use crate::state::AppState;

pub async fn create_user(
    State(state): State<AppState>,
    ValidatedJson(input): ValidatedJson<CreateUser>,
) -> Result<Json<ApiResponse<UserDTO>>, AppError> {
    // Check username uniqueness
    if UserRepo::find_by_username(&state.db, &input.username).await?.is_some() {
        return Err(AppError::Conflict(format!("username '{}' already exists", input.username)));
    }

    let password_hash = bcrypt::hash(&input.password, bcrypt::DEFAULT_COST)
        .map_err(|e| AppError::Internal(format!("Password hash error: {e}")))?;

    let user = UserRepo::create(&state.db, &input, &password_hash).await?;
    Ok(Json(ApiResponse::success(UserDTO::from(user))))
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
    Ok(Json(ApiResponse::success(UserDTO::from(user))))
}

pub async fn update_user(
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
    ValidatedJson(input): ValidatedJson<UpdateUser>,
) -> Result<Json<ApiResponse<UserDTO>>, AppError> {
    let user = UserRepo::update(&state.db, id, &input).await?;
    Ok(Json(ApiResponse::success(UserDTO::from(user))))
}

pub async fn delete_user(
    State(state): State<AppState>,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<ApiResponse<()>>, AppError> {
    UserRepo::delete(&state.db, id).await?;
    Ok(Json(ApiResponse::<()>::success_message("user deleted")))
}
