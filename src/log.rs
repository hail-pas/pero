use tracing_subscriber::prelude::*;
use tracing_subscriber::EnvFilter;
use crate::config::LogConfig;

pub fn init(cfg: &LogConfig) {
    let file_appender = tracing_appender::rolling::daily(&cfg.dir, "pero.log");
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

    // Keep the guard alive for the process lifetime
    std::mem::forget(_guard);

    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(&cfg.level));

    let stdout_layer = tracing_subscriber::fmt::layer()
        .with_target(false);

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
