use crate::api::extractors::{AuthUser, ValidatedJson};
use crate::api::response::MessageResponse;
use crate::domain::auth::service::AuthService;
use crate::domain::user::models::ChangePasswordRequest;
use crate::shared::error::AppError;
use crate::shared::state::AppState;
use axum::Json;
use axum::extract::State;
#[utoipa::path(
    put,
    path = "/api/identity/password/change",
    tag = "Identity",
    request_body = crate::api::schemas::user::ChangePasswordRequest,
    responses(
        (status = 200, description = "Password changed", body = crate::api::response::MessageResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn change_password(
    State(state): State<AppState>,
    auth_user: AuthUser,
    ValidatedJson(req): ValidatedJson<ChangePasswordRequest>,
) -> Result<Json<MessageResponse>, AppError> {
    AuthService::change_password(
        &*state.repos.users,
        &*state.repos.identities,
        &*state.repos.sessions,
        &*state.repos.refresh_tokens,
        auth_user.user_id,
        &req.old_password,
        &req.new_password,
    )
    .await?;

    Ok(Json(MessageResponse::success("password changed")))
}
