pub mod health;
pub mod jwks;
pub mod providers;
pub mod token;
pub mod userinfo;

use axum::Router;
use axum::routing::{get, post};

pub fn routes() -> Router<crate::state::app::AppState> {
    Router::new()
        .route("/health", get(health::health))
        .route("/ready", get(health::ready))
        .route("/oauth2/token", post(token::token))
        .route("/oauth2/jwks", get(jwks::jwks))
        .route("/oauth2/userinfo", get(userinfo::userinfo))
        .route("/providers", get(providers::providers))
}
