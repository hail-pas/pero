use axum::extract::{Query, State};
use axum::response::{IntoResponse, Response};
use axum_extra::extract::CookieJar;
use serde::Deserialize;

use crate::cookie;
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct LoginQuery {
    #[serde(default)]
    pub error: String,
}

pub async fn login_page(
    State(state): State<AppState>,
    Query(query): Query<LoginQuery>,
    jar: CookieJar,
) -> Response {
    if matches!(
        crate::middleware::authenticated_user(&state, &jar).await,
        Ok(Some(_))
    ) {
        return (
            axum::http::StatusCode::FOUND,
            [("Location", "/".to_owned())],
        )
            .into_response();
    }

    let issuer = &state.config.oauth2.issuer;
    let scopes = &state.config.oauth2.scopes;
    let pkce = pero_utils::oauth::pkce::PkcePair::generate();
    let state_param = pero_utils::oauth::url::generate_state();
    let scope = scopes.join(" ");
    let endpoint = pero_utils::oauth::url::issuer_endpoint(issuer, "oauth2/authorize");
    let authorize_url =
        pero_utils::oauth::url::build_authorize_url(&pero_utils::oauth::url::AuthorizeUrlParams {
            endpoint: &endpoint,
            client_id: &state.config.oauth2.client_id,
            redirect_uri: &state.config.oauth2.redirect_uri,
            scope: &scope,
            state: &state_param,
            code_challenge: &pkce.code_challenge,
            prompt: None,
        });

    let template = crate::handler::dto::AdminLoginView {
        error: query.error,
        authorize_url,
    };

    let jar = cookie::set_pkce_cookies(jar, &pkce.code_verifier, &state_param, &state.config);

    (jar, pero_api_axum::form::view("AdminLoginView", template)).into_response()
}
