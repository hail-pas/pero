use crate::config::LogConfig;
use std::sync::{Mutex, OnceLock};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::prelude::*;

static LOG_GUARD: OnceLock<Mutex<Option<WorkerGuard>>> = OnceLock::new();

pub fn init(cfg: &LogConfig) {
    let file_appender = match cfg.rotation.as_str() {
        "hourly" => tracing_appender::rolling::hourly(&cfg.dir, "pero.log"),
        _ => tracing_appender::rolling::daily(&cfg.dir, "pero.log"),
    };
    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
    LOG_GUARD
        .set(Mutex::new(Some(guard)))
        .expect("log guard already initialized");

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

pub fn flush() {
    if let Some(mutex) = LOG_GUARD.get() {
        if let Some(guard) = mutex.lock().ok().and_then(|mut g| g.take()) {
            drop(guard);
        }
    }
}
