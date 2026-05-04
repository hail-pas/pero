use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};

use crate::api::extractors::ValidatedForm;
use crate::application::token_exchange;
use crate::domain::oauth::models::RevokeRequest;
use crate::domain::oauth::service;
use crate::infra::http::oauth2 as error;
use crate::shared::state::AppState;

pub async fn revoke(
    State(state): State<AppState>,
    headers: HeaderMap,
    ValidatedForm(req): ValidatedForm<RevokeRequest>,
) -> Response {
    let auth_header = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    let req = match service::resolve_client_credentials(auth_header, req) {
        Ok(req) => req,
        Err(e) => return error::map_app_error(e),
    };
    match token_exchange::revoke_token(
        &*state.repos.oauth2_clients,
        &*state.repos.refresh_tokens,
        &*state.repos.apps,
        &req,
    )
    .await
    {
        Ok(()) => StatusCode::OK.into_response(),
        Err(e) => error::map_app_error(e),
    }
}
