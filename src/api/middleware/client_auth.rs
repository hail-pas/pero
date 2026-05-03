use crate::domain::oauth2::service::{self, InvalidClientError};
use crate::shared::error::AppError;
use crate::shared::state::AppState;
use axum::extract::{Request, State};
use axum::http::header;
use axum::middleware::Next;
use axum::response::Response;

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

    let (client_id, client_secret) = service::parse_basic_client_auth_header(auth_header)?;
    let client = service::authenticate_client(
        &*state.repos.oauth2_clients,
        &*state.repos.apps,
        &client_id,
        &client_secret,
        None,
        true,
        InvalidClientError::Unauthorized,
    )
    .await?;

    req.extensions_mut().insert(client);
    Ok(next.run(req).await)
}
