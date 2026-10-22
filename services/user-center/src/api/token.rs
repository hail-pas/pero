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
    axum::Form(form): axum::Form<TokenRequest>,
) -> Response {
    match TokenService::new(&state)
        .token(&form, &source.for_rate_limit())
        .await
    {
        TokenEndpointResult::Success(body) => token_success_response(body),
        TokenEndpointResult::Error { code, desc } => token_error_response(code, desc.as_deref()),
        TokenEndpointResult::Unauthorized(desc) => token_error_unauthorized_response(&desc),
    }
}
