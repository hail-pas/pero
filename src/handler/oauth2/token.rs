use crate::api::extractors::ValidatedForm;
use crate::application::token_exchange;
use crate::domain::oauth::models::TokenRequest;
use crate::domain::oauth::service;
use crate::infra::http::oauth2 as error;
use crate::shared::state::AppState;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};

#[utoipa::path(
    post,
    path = "/oauth2/token",
    tag = "OAuth2",
    request_body(
        content = crate::domain::oauth::models::TokenRequest,
        content_type = "application/x-www-form-urlencoded",
    ),
    responses(
        (status = 200, description = "Token response", body = crate::domain::oauth::models::TokenResponse),
        (status = 400, description = "Invalid request"),
    )
)]
pub async fn token(
    State(state): State<AppState>,
    headers: HeaderMap,
    ValidatedForm(req): ValidatedForm<TokenRequest>,
) -> Response {
    let auth_header = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());
    let req = match service::resolve_client_credentials(auth_header, req) {
        Ok(req) => req,
        Err(e) => return error::map_app_error(e),
    };
    match token_exchange::exchange_token(
        &*state.repos.oauth2_clients,
        &*state.repos.refresh_tokens,
        &*state.repos.token_families,
        &*state.repos.apps,
        &*state.repos.users,
        &*state.repos.token_signer,
        state.config.oauth2.access_token_ttl_minutes,
        state.config.oauth2.refresh_token_ttl_days,
        &state.config.oidc.issuer,
        &req,
    )
    .await
    {
        Ok(response) => axum::Json(response).into_response(),
        Err(e) => error::map_app_error(e),
    }
}
