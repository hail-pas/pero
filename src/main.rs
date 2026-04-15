mod auth;
mod cache;
mod config;
mod db;
mod error;
mod extractors;
mod log;
mod middleware;
mod response;
mod routes;
mod state;

use config::AppConfig;
use std::sync::Arc;

#[tokio::main]
async fn main() {
    let cfg = AppConfig::load().expect("Failed to load configuration");
    log::init(&cfg.log);

    let db_pool = db::init_pool(&cfg.database).await.expect("Failed to init database");
    let cache_pool = cache::init_pool(&cfg.redis).await.expect("Failed to init redis");

    let state = state::AppState {
        db: db_pool,
        cache: cache_pool,
        config: Arc::new(cfg),
    };

    let addr = format!(
        "{}:{}",
        state.config.server.host,
        state.config.server.port
    );

    let app = routes::build_router(state);

    let listener = tokio::net::TcpListener::bind(&addr).await.expect("Failed to bind address");

    tracing::info!("Server listening on {}", addr);
    axum::serve(listener, app).await.expect("Server error");
}
