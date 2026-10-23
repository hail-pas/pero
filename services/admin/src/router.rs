use axum::Router;
use axum::middleware;
use pero_api_axum::middleware::cors_layer;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::services::ServeDir;

use crate::handler;
use crate::middleware::require_auth;
use crate::state::AppState;

async fn not_found() -> impl axum::response::IntoResponse {
    (
        axum::http::StatusCode::NOT_FOUND,
        axum::Json(serde_json::json!({"view":"ErrorView","data":{"code":"404"}})),
    )
}

pub fn build(state: AppState) -> Router {
    let static_dir = state.config.frontend.static_dir.clone();

    let protected = Router::new()
        .route("/", axum::routing::get(handler::home::home))
        .layer(middleware::from_fn_with_state(state.clone(), require_auth));

    let page_directory = static_dir.clone();
    let pages = Router::new()
        .route("/login", axum::routing::get(handler::login::login_page))
        .merge(protected)
        .route_layer(middleware::from_fn(move |req, next| {
            let directory = page_directory.clone();
            async move { pero_api_axum::spa::serve_page(req, next, directory).await }
        }));

    Router::new()
        .merge(pages)
        .route("/callback", axum::routing::get(handler::callback::callback))
        .route("/logout", axum::routing::post(handler::logout::logout))
        .fallback(not_found)
        .nest_service("/static", ServeDir::new(static_dir.clone()))
        .layer(middleware::from_fn(move |req, next| {
            let directory = static_dir.clone();
            async move { pero_api_axum::spa::serve(req, next, directory).await }
        }))
        .layer(middleware::from_fn(
            pero_api_axum::headers::security_headers,
        ))
        .layer(RequestBodyLimitLayer::new(
            state.config.server.request_body_limit_bytes,
        ))
        .layer(cors_layer(&state.config.server.cors))
        .layer(pero_api_axum::middleware::tracing_layer(
            state.config.log.clone(),
        ))
        .with_state(state)
}
