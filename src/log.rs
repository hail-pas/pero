use crate::config::LogConfig;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::prelude::*;

pub fn init(cfg: &LogConfig) {
    let file_appender = match cfg.rotation.as_str() {
        "hourly" => tracing_appender::rolling::hourly(&cfg.dir, "pero.log"),
        _ => tracing_appender::rolling::daily(&cfg.dir, "pero.log"),
    };
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);
    // Intentionally leak the guard: for a long-running server this prevents
    // the non-blocking writer from being dropped, which would flush on shutdown.
    // If graceful shutdown is needed, store the guard and call `.flush()` explicitly.
    std::mem::forget(_guard);

    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&cfg.level));

    let stdout_layer = tracing_subscriber::fmt::layer().with_target(false);
    let file_layer = tracing_subscriber::fmt::layer()
        .json()
        .with_writer(non_blocking)
        .with_target(true);

    tracing_subscriber::registry()
        .with(env_filter)
        .with(stdout_layer)
        .with(file_layer)
        .init();
}
