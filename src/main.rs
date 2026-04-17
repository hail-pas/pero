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
        discovery_doc: Arc::new(std::sync::OnceLock::new()),
        jwks_doc: Arc::new(std::sync::OnceLock::new()),
    };

    let addr = if state.config.server.host.contains(':') {
        format!(
            "[{}]:{}",
            state.config.server.host, state.config.server.port
        )
    } else {
        format!("{}:{}", state.config.server.host, state.config.server.port)
    };

    let app = pero::app::build_router(state);

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("Failed to bind address");

    tracing::info!("Server listening on {}", addr);
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .expect("Server error");
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            tracing::info!("received Ctrl+C, shutting down");
        },
        _ = terminate => {
            tracing::info!("received SIGTERM, shutting down");
        },
    }
}
