use crate::shared::state::AppState;
use axum::Json;
use axum::extract::State;

pub async fn jwks(State(state): State<AppState>) -> Json<serde_json::Value> {
    let doc = state.jwks_doc.get_or_init(|| {
        let key = state.jwt_keys.public_key_jwk();
        serde_json::json!({ "keys": [key] })
    });
    Json(doc.clone())
}
