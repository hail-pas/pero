use axum::extract::State;
use axum::Json;
use crate::domains::identity::models::ChangePasswordRequest;
use crate::domains::identity::repos::IdentityRepo;
use crate::shared::error::AppError;
use crate::shared::extractors::{AuthUser, ValidatedJson};
use crate::shared::response::ApiResponse;
use crate::shared::state::AppState;

pub async fn change_password(
    State(state): State<AppState>,
    auth_user: AuthUser,
    ValidatedJson(req): ValidatedJson<ChangePasswordRequest>,
) -> Result<Json<ApiResponse<()>>, AppError> {
    let identity = IdentityRepo::find_by_user_and_provider(&state.db, auth_user.user_id, "password")
        .await?
        .ok_or(AppError::NotFound("password identity".into()))?;

    let credential = identity.credential.as_deref().ok_or(AppError::NotFound("password identity".into()))?;

    let valid = bcrypt::verify(&req.old_password, credential)
        .map_err(|e| AppError::Internal(format!("Password verify error: {e}")))?;
    if !valid {
        return Err(AppError::BadRequest("old password is incorrect".into()));
    }

    let new_hash = bcrypt::hash(&req.new_password, bcrypt::DEFAULT_COST)
        .map_err(|e| AppError::Internal(format!("Password hash error: {e}")))?;

    IdentityRepo::update_credential(&state.db, auth_user.user_id, "password", &new_hash).await?;

    Ok(Json(ApiResponse::<()>::success_message("password changed")))
}
