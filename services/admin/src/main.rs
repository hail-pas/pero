use std::path::PathBuf;

use clap::Parser;
use pero_config::ConfigLoader;
use pero_validate_core::{Validatable, ValidationResult};

use admin::config::AppConfig;
use admin::router;
use admin::state::AppState;

#[derive(Debug, Parser)]
#[command(name = "admin", version, about = "Admin panel service")]
struct Cli {
    #[arg(
        long,
        value_name = "DIR",
        default_value = "config",
        help = "Path to the config directory holding *.toml files"
    )]
    config_dir: PathBuf,
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to install Ctrl+C handler");
    tracing::info!("received Ctrl+C, shutting down");
}

#[tokio::main]
async fn main() -> ValidationResult {
    let cli = Cli::parse();
    let app_config = ConfigLoader::new()
        .config_dir(&cli.config_dir)
        .load::<AppConfig>()?;
    app_config.validate()?;

    let _log_guard = app_config.log.init()?;

    let state = AppState::new(app_config);
    let addr = format!("{}:{}", state.config.server.host, state.config.server.port);
    let app = router::build(state);

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("Failed to bind address");

    tracing::info!("Admin panel listening on {}", addr);
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .expect("Server error");

    tracing::info!("shutdown complete");
    Ok(())
}
