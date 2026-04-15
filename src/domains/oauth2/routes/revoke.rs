use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;

use crate::domains::oauth2::models::RevokeRequest;
use crate::domains::oauth2::repos::RefreshTokenRepo;
use crate::shared::error::AppError;
use crate::shared::state::AppState;

pub async fn revoke(
    State(state): State<AppState>,
    Json(req): Json<RevokeRequest>,
) -> Result<Response, AppError> {
    if let Some(token) = RefreshTokenRepo::find_by_token(&state.db, &req.token).await? {
        RefreshTokenRepo::revoke(&state.db, token.id).await?;
    }
    Ok(StatusCode::OK.into_response())
}
