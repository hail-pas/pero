use axum::extract::State;
use axum::response::Response;
use pero_api_axum::oauth::{
    token_error_response, token_error_unauthorized_response, token_success_response,
};

use crate::service::token::{TokenEndpointResult, TokenRequest, TokenService};
use crate::state::app::AppState;

pub async fn token(
    State(state): State<AppState>,
    source: pero_api_axum::extractor::ClientIp,
    headers: axum::http::HeaderMap,
    axum::Form(mut form): axum::Form<TokenRequest>,
) -> Response {
    if let Err(e) =
        super::client_auth::apply(&headers, &mut form.client_id, &mut form.client_secret)
    {
        return token_error_unauthorized_response(e);
    }
    match TokenService::new(&state)
        .token(&form, &source.for_rate_limit())
        .await
    {
        TokenEndpointResult::Success(body) => token_success_response(body),
        TokenEndpointResult::Error { code, desc } => token_error_response(code, desc.as_deref()),
        TokenEndpointResult::Unauthorized(desc) => token_error_unauthorized_response(&desc),
    }
}
