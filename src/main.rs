use pero::config::AppConfig;
use pero::infra::jwt::JwtKeys;
use pero::shared::state::AppState;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

#[tokio::main]
async fn main() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    let cfg = AppConfig::load().expect("Failed to load configuration");
    pero::infra::logging::init(&cfg.log);

    validate_production_config(&cfg);

    let db_pool = pero::infra::db::init_pool(&cfg.database)
        .await
        .expect("Failed to init database");
    let cache_pool = pero::infra::cache::init_pool(&cfg.redis)
        .await
        .expect("Failed to init redis");

    let jwt_keys = Arc::new(JwtKeys::load(&cfg.oidc).expect("Failed to load JWT keys"));

    let cleanup_interval = Duration::from_secs(cfg.server.cleanup_interval_secs);
    let janitor_db = db_pool.clone();
    tokio::spawn(async move {
        pero::infra::janitor::run(janitor_db, cleanup_interval).await;
    });

    let repos = pero::infra::repo::build_repos(db_pool, cache_pool, jwt_keys.clone(), &cfg);
    let state = AppState {
        repos: Arc::new(repos),
        jwt_keys,
        config: Arc::new(cfg),
        discovery_doc: Arc::new(OnceLock::new()),
        jwks_doc: Arc::new(OnceLock::new()),
    };

    let addr = if state.config.server.host.contains(':') {
        format!(
            "[{}]:{}",
            state.config.server.host, state.config.server.port
        )
    } else {
        format!("{}:{}", state.config.server.host, state.config.server.port)
    };

    let app = pero::api::build_router(state);

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("Failed to bind address");

    tracing::info!("Server listening on {}", addr);
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .expect("Server error");

    pero::infra::logging::flush();
    tracing::info!("shutdown complete");
}

fn validate_production_config(cfg: &AppConfig) {
    let run_mode = std::env::var("RUN_MODE").unwrap_or_else(|_| "development".into());
    if run_mode != "production" {
        return;
    }

    if !cfg.sso.cookie_secure {
        tracing::error!("FATAL: cookie_secure must be true in production");
        std::process::exit(1);
    }
    if cfg.cors.allow_origins.iter().any(|o| o == "*") {
        tracing::error!("FATAL: CORS allow_origins must not be '*' in production");
        std::process::exit(1);
    }
    if !cfg.oidc.issuer.starts_with("https://") {
        tracing::error!("FATAL: OIDC issuer must use HTTPS in production");
        std::process::exit(1);
    }
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
