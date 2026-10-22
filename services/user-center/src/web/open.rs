use axum::extract::State;
use axum::response::{IntoResponse, Response};
use serde::Serialize;

use crate::state::app::AppState;

#[derive(Debug, Serialize)]
pub struct OpenIdConfiguration {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: String,
    pub jwks_uri: String,
    pub end_session_endpoint: String,
    pub response_types_supported: Vec<&'static str>,
    pub subject_types_supported: Vec<&'static str>,
    pub id_token_signing_alg_values_supported: Vec<&'static str>,
    pub scopes_supported: Vec<&'static str>,
    pub token_endpoint_auth_methods_supported: Vec<&'static str>,
    pub claims_supported: Vec<&'static str>,
    pub code_challenge_methods_supported: Vec<&'static str>,
    pub grant_types_supported: Vec<&'static str>,
}

pub async fn openid_configuration(State(state): State<AppState>) -> Response {
    let issuer = &state.config.oidc.issuer;
    let base = issuer.trim_end_matches('/');

    let doc = OpenIdConfiguration {
        issuer: issuer.clone(),
        authorization_endpoint: format!("{base}/oauth2/authorize"),
        token_endpoint: format!("{base}/api/oauth2/token"),
        userinfo_endpoint: format!("{base}/api/oauth2/userinfo"),
        jwks_uri: format!("{base}/api/oauth2/jwks"),
        end_session_endpoint: format!("{base}/oauth2/session/end"),
        response_types_supported: vec!["code"],
        subject_types_supported: vec!["public"],
        id_token_signing_alg_values_supported: vec!["RS256"],
        scopes_supported: vec!["openid", "profile", "email", "phone"],
        token_endpoint_auth_methods_supported: vec!["client_secret_post"],
        claims_supported: vec![
            "iss",
            "sub",
            "aud",
            "exp",
            "iat",
            "nonce",
            "at_hash",
            "c_hash",
            "name",
            "email",
            "email_verified",
            "phone_number",
            "phone_number_verified",
            "preferred_username",
            "picture",
            "sid",
        ],
        code_challenge_methods_supported: vec!["S256"],
        grant_types_supported: vec!["authorization_code", "refresh_token"],
    };

    (
        axum::http::StatusCode::OK,
        [
            (
                axum::http::header::CONTENT_TYPE,
                "application/json; charset=utf-8",
            ),
            (axum::http::header::CACHE_CONTROL, "public, max-age=3600"),
        ],
        serde_json::to_string(&doc).unwrap_or_default(),
    )
        .into_response()
}
