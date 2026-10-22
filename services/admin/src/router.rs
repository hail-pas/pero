use axum::Router;
use axum::middleware;
use pero_api_axum::middleware::cors_layer;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::services::ServeDir;

use crate::handler;
use crate::middleware::require_auth;
use crate::state::AppState;

async fn not_found() -> impl axum::response::IntoResponse {
    (axum::http::StatusCode::NOT_FOUND, "404 Not Found")
}

pub fn build(state: AppState) -> Router {
    let static_dir = state.config.askama.static_dir.clone();
    let static_url = state.config.askama.static_url_prefix.clone();

    let public = Router::new()
        .route("/login", axum::routing::get(handler::login::login_page))
        .route("/callback", axum::routing::get(handler::callback::callback));

    let protected = Router::new()
        .route("/", axum::routing::get(handler::home::home))
        .layer(middleware::from_fn_with_state(state.clone(), require_auth));

    Router::new()
        .merge(public)
        .merge(protected)
        .route("/logout", axum::routing::post(handler::logout::logout))
        .fallback(not_found)
        .nest_service(&static_url, ServeDir::new(static_dir))
        .layer(RequestBodyLimitLayer::new(
            state.config.server.request_body_limit_bytes,
        ))
        .layer(cors_layer(&state.config.server.cors))
        .layer(pero_api_axum::middleware::tracing_layer(
            state.config.log.clone(),
        ))
        .with_state(state)
}
