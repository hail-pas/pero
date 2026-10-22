use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;
use pero_cache_redis::RedisCacheStore;
use pero_config::{ConfigLoader, RuntimeOption};
use pero_http_client_reqwest::ReqwestHttpClient;
use pero_validate_core::{Validatable, ValidationResult};
use user_center::config;
use user_center::db::init::init_db;
use user_center::router;
use user_center::state::app::AppState;
use user_center::task::start_cleanup_task;

#[derive(Debug, Parser)]
#[command(name = "user-center", version, about = "User center service")]
struct Cli {
    #[arg(
        long,
        value_name = "DIR",
        default_value = "config",
        help = "Path to the config directory holding *.toml files"
    )]
    config_dir: PathBuf,
}

async fn wait_for_signal() {
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

#[tokio::main]
async fn main() -> ValidationResult {
    let cli = Cli::parse();
    let rt = RuntimeOption {
        config_dir: cli.config_dir,
    };
    rt.validate()?;
    let app_config = ConfigLoader::new()
        .config_dir(&rt.config_dir)
        .load::<config::AppConfig>()?;
    let log_guard = app_config.log.init()?;

    let (db, db_guard) = init_db(&app_config).await?;

    let cache = RedisCacheStore::from_config(&app_config.redis)?;
    let http_client = ReqwestHttpClient::from_public_config(&app_config.http_config)?;

    let cleanup_handle = start_cleanup_task(db.clone(), app_config.server.cleanup_interval_secs);

    let graceful_timeout = Duration::from_secs(app_config.server.graceful_shutdown_timeout_secs);

    let addr = format!("{}:{}", app_config.server.host, app_config.server.port);
    let state = AppState::new(app_config, db, cache, http_client);
    let delivery_handle = user_center::service::notify::start_delivery_task(state.clone());
    let app = router::build(state);

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("Failed to bind address");

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let server_handle = tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .with_graceful_shutdown(async {
            shutdown_rx.await.ok();
        })
        .await
        .expect("Server error");
    });

    tracing::info!("Server listening on {}", addr);

    wait_for_signal().await;

    tracing::info!(
        timeout_secs = graceful_timeout.as_secs(),
        "graceful shutdown initiated, waiting for in-flight requests"
    );
    let _ = shutdown_tx.send(());

    match tokio::time::timeout(graceful_timeout, server_handle).await {
        Ok(Ok(())) => tracing::info!("server shut down gracefully"),
        Ok(Err(e)) => tracing::error!(error = %e, "server error during shutdown"),
        Err(_) => tracing::warn!(
            timeout_secs = graceful_timeout.as_secs(),
            "graceful shutdown timed out, forcing stop"
        ),
    }

    delivery_handle.abort();
    cleanup_handle.abort();
    tracing::info!("cleanup task stopped");
    db_guard.shutdown().await;
    log_guard.shutdown();

    Ok(())
}
