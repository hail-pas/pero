use pero::config::AppConfig;
use pero::shared::state::AppState;
use std::sync::Arc;

#[tokio::main]
async fn main() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    let cfg = AppConfig::load().expect("Failed to load configuration");
    pero::log::init(&cfg.log);

    let db_pool = pero::db::init_pool(&cfg.database)
        .await
        .expect("Failed to init database");
    let cache_pool = pero::cache::init_pool(&cfg.redis)
        .await
        .expect("Failed to init redis");

    let jwt_keys = pero::shared::jwt::JwtKeys::load(&cfg.oidc).expect("Failed to load JWT keys");

    let state = AppState {
        db: db_pool,
        cache: cache_pool,
        config: Arc::new(cfg),
        jwt_keys: Arc::new(jwt_keys),
    };

    let addr = format!("{}:{}", state.config.server.host, state.config.server.port);

    let app = pero::app::build_router(state);

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("Failed to bind address");

    tracing::info!("Server listening on {}", addr);
    axum::serve(listener, app).await.expect("Server error");
}
