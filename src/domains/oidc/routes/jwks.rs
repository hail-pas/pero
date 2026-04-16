use crate::shared::state::AppState;
use axum::Json;
use axum::extract::State;

#[utoipa::path(
    get,
    path = "/oauth2/keys",
    tag = "OIDC",
    responses(
        (status = 200, description = "JWKS public key set")
    )
)]
pub async fn jwks(State(state): State<AppState>) -> Json<serde_json::Value> {
    let key = state.jwt_keys.public_key_jwk();
    Json(serde_json::json!({
        "keys": [key]
    }))
}
