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
    let issuer = &state.config.oidc.issuer;
    Json(serde_json::json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/oauth2/authorize"),
        "token_endpoint": format!("{issuer}/oauth2/token"),
        "userinfo_endpoint": format!("{issuer}/oauth2/userinfo"),
        "jwks_uri": format!("{issuer}/oauth2/keys"),
        "revocation_endpoint": format!("{issuer}/oauth2/revoke"),
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "profile", "email", "phone"],
        "token_endpoint_auth_methods_supported": ["client_secret_post"],
        "claims_supported": [
            "sub", "iss", "aud", "exp", "iat", "auth_time", "nonce",
            "name", "nickname", "picture",
            "email", "email_verified",
            "phone_number", "phone_number_verified"
        ],
        "code_challenge_methods_supported": ["S256"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
    }))
}
