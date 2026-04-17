use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

use crate::domains::oauth2::models::RevokeRequest;
use crate::domains::oauth2::repos::{OAuth2ClientRepo, RefreshTokenRepo};
use crate::shared::error::AppError;
use crate::shared::extractors::ValidatedJson;
use crate::shared::state::AppState;

#[utoipa::path(
    post,
    path = "/oauth2/revoke",
    tag = "OAuth2",
    request_body = crate::domains::oauth2::models::RevokeRequest,
    responses(
        (status = 200, description = "Token revoked"),
        (status = 400, description = "Invalid request"),
    )
)]
pub async fn revoke(
    State(state): State<AppState>,
    ValidatedJson(req): ValidatedJson<RevokeRequest>,
) -> Result<Response, AppError> {
    let client_id_str = req
        .client_id
        .as_deref()
        .ok_or(AppError::BadRequest("missing client_id".into()))?;
    let client_secret = req
        .client_secret
        .as_deref()
        .ok_or(AppError::BadRequest("missing client_secret".into()))?;

    let client = OAuth2ClientRepo::find_by_client_id(&state.db, client_id_str)
        .await?
        .ok_or(AppError::BadRequest("invalid client_id".into()))?;
    let valid = bcrypt::verify(client_secret, &client.client_secret_hash)
        .map_err(|e| AppError::Internal(format!("Secret verify error: {e}")))?;
    if !valid {
        return Err(AppError::Unauthorized);
    }

    if let Some(token) = RefreshTokenRepo::find_by_token(&state.db, &req.token).await? {
        RefreshTokenRepo::revoke(&state.db, token.id).await?;
    }
    Ok(StatusCode::OK.into_response())
}
