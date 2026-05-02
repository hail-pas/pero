use crate::shared::constants::jwt as jwt_constants;
use crate::shared::constants::oauth2 as oauth2_constants;
use crate::shared::constants::oauth2::scopes as oauth2_scopes;
use crate::shared::state::AppState;
use axum::Json;
use axum::extract::State;

#[utoipa::path(
    get,
    path = "/.well-known/openid-configuration",
    tag = "OIDC",
    responses(
        (status = 200, description = "OIDC Discovery document")
    )
)]
pub async fn discovery(State(state): State<AppState>) -> Json<serde_json::Value> {
    let doc = state.discovery_doc.get_or_init(|| build_discovery(&state));
    Json(doc.clone())
}

fn build_discovery(state: &AppState) -> serde_json::Value {
    let issuer = &state.config.oidc.issuer;
    serde_json::json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/oauth2/authorize"),
        "token_endpoint": format!("{issuer}/oauth2/token"),
        "userinfo_endpoint": format!("{issuer}/oauth2/userinfo"),
        "jwks_uri": format!("{issuer}/oauth2/keys"),
        "revocation_endpoint": format!("{issuer}/oauth2/revoke"),
        "end_session_endpoint": format!("{issuer}/oauth2/session/end"),
        "response_types_supported": [oauth2_constants::RESPONSE_TYPE_CODE],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": [jwt_constants::ALG_RS256],
        "scopes_supported": [oauth2_scopes::OPENID, oauth2_scopes::PROFILE, oauth2_scopes::EMAIL, oauth2_scopes::PHONE],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        "claims_supported": [
            "sub", "iss", "aud", "exp", "iat", "auth_time", "nonce",
            "name", "nickname", "picture",
            "email", "email_verified",
            "phone_number", "phone_number_verified"
        ],
        "code_challenge_methods_supported": [oauth2_constants::PKCE_METHOD_S256],
        "grant_types_supported": [oauth2_constants::GRANT_TYPE_AUTH_CODE, oauth2_constants::GRANT_TYPE_REFRESH_TOKEN],
    })
}
