use crate::domains::oauth2::repos::OAuth2ClientRepo;
use crate::shared::error::AppError;
use crate::shared::state::AppState;
use axum::extract::{Request, State};
use axum::http::header;
use axum::middleware::Next;
use axum::response::Response;
use base64::Engine;

pub async fn client_credentials_middleware(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Result<Response, AppError> {
    let auth_header = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or(AppError::Unauthorized)?;

    let (client_id, client_secret) = if let Some(encoded) = auth_header
        .strip_prefix("Basic ")
        .or_else(|| auth_header.strip_prefix("basic "))
    {
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|_| AppError::Unauthorized)?;
        let decoded_str = String::from_utf8(decoded).map_err(|_| AppError::Unauthorized)?;
        let mut parts = decoded_str.splitn(2, ':');
        let cid = parts.next().unwrap_or("");
        let csecret = parts.next().unwrap_or("");
        if cid.is_empty() || csecret.is_empty() {
            return Err(AppError::Unauthorized);
        }
        (cid.to_string(), csecret.to_string())
    } else {
        return Err(AppError::BadRequest("Expected Basic auth".into()));
    };

    let client = match OAuth2ClientRepo::find_by_client_id(&state.db, &client_id).await? {
        Some(c) => c,
        None => {
            let _ = bcrypt::verify(
                &client_secret,
                "$2b$12$TrePSBin7KMS2YzgKJgNXeSKHaFjHOa/XYRm8kqDQoJHqWbsLCDKi",
            );
            return Err(AppError::Unauthorized);
        }
    };

    if !client.enabled {
        return Err(AppError::Forbidden("client is disabled".into()));
    }

    let valid = bcrypt::verify(&client_secret, &client.client_secret_hash)
        .map_err(|e| AppError::Internal(format!("Secret verify error: {e}")))?;
    if !valid {
        return Err(AppError::Unauthorized);
    }

    req.extensions_mut().insert(client);
    Ok(next.run(req).await)
}
