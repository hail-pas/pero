use axum::extract::{Path, State};
use axum::Json;
use crate::domains::identity::models::BindRequest;
use crate::domains::identity::repos::IdentityRepo;
use crate::shared::error::AppError;
use crate::shared::extractors::AuthUser;
use crate::shared::response::ApiResponse;
use crate::shared::state::AppState;

pub async fn bind(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path(provider): Path<String>,
    Json(_req): Json<BindRequest>,
) -> Result<Json<ApiResponse<()>>, AppError> {
    let existing = IdentityRepo::find_by_user_and_provider(&state.db, auth_user.user_id, &provider).await?;
    if existing.is_some() {
        return Err(AppError::Conflict(format!("provider '{}' already bound", provider)));
    }

    // TODO: 用 _req.code + _req.redirect_uri 与第三方 provider 交换 access_token，
    //       获取 provider_uid，然后调用 IdentityRepo::create_oauth。
    //       目前需要先集成 oauth2 crate 或手动 HTTP 调用各 provider 的 token/userinfo 端点。
    Err(AppError::BadRequest(format!("provider '{}' binding not yet implemented", provider)))
}

pub async fn unbind(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Path(provider): Path<String>,
) -> Result<Json<ApiResponse<()>>, AppError> {
    if provider == "password" {
        return Err(AppError::BadRequest("cannot unbind password identity".into()));
    }

    let count = IdentityRepo::count_by_user(&state.db, auth_user.user_id).await?;
    if count <= 1 {
        return Err(AppError::BadRequest("must keep at least one login method".into()));
    }

    IdentityRepo::delete(&state.db, auth_user.user_id, &provider).await?;

    Ok(Json(ApiResponse::<()>::success_message("provider unbound")))
}
