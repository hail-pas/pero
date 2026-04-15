use crate::shared::state::AppState;
use axum::Json;
use axum::extract::State;

pub async fn jwks(State(state): State<AppState>) -> Json<serde_json::Value> {
    let key = state.jwt_keys.public_key_jwk();
    Json(serde_json::json!({
        "keys": [key]
    }))
}
