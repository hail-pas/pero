use crate::api::extractors::{AuthUser, ValidatedJson};
use crate::api::response::MessageResponse;
use crate::domain::identity::authn::AuthService;
use crate::domain::identity::models::ChangePasswordRequest;
use crate::shared::error::AppError;
use crate::shared::state::AppState;
use axum::Json;
use axum::extract::State;
use utoipa;

#[utoipa::path(
    put,
    path = "/api/identity/password/change",
    tag = "Identity",
    security(("bearer_auth" = [])),
    request_body = ChangePasswordRequest,
    responses(
        (status = 200, description = "Password changed", body = MessageResponse),
        (status = 400, description = "Old password incorrect"),
        (status = 401, description = "Unauthorized"),
    )
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
        &*state.repos.oauth2_tokens,
        auth_user.user_id,
        &req.old_password,
        &req.new_password,
    )
    .await?;

    Ok(Json(MessageResponse::success("password changed")))
}
