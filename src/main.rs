mod app;
mod cache;
mod config;
mod db;
mod domains;
mod log;
mod routes;
mod shared;

use config::AppConfig;
use shared::state::AppState;
use std::sync::Arc;

#[tokio::main]
async fn main() {
    let cfg = AppConfig::load().expect("Failed to load configuration");
    log::init(&cfg.log);

    let db_pool = db::init_pool(&cfg.database)
        .await
        .expect("Failed to init database");
    let cache_pool = cache::init_pool(&cfg.redis)
        .await
        .expect("Failed to init redis");

    let jwt_keys = crate::shared::jwt::JwtKeys::load(&cfg.oidc).expect("Failed to load JWT keys");

    let state = AppState {
        db: db_pool,
        cache: cache_pool,
        config: Arc::new(cfg),
        jwt_keys: Arc::new(jwt_keys),
    };

    let addr = format!("{}:{}", state.config.server.host, state.config.server.port);

    let app = app::build_router(state);

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("Failed to bind address");

    tracing::info!("Server listening on {}", addr);
    axum::serve(listener, app).await.expect("Server error");
}
