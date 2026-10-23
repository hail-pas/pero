use pero_validate_core::{
    Validatable, ValidationError, ValidationIssue, ValidationReport, ValidationResult,
};
use serde::Deserialize;
use std::path::{Path, PathBuf};

use tracing_appender::{
    non_blocking::WorkerGuard,
    rolling::{self, RollingFileAppender},
};
use tracing_subscriber::{
    filter::LevelFilter,
    fmt::writer::{BoxMakeWriter, MakeWriterExt},
};

const DEFAULT_LOG_FILE_NAME: &str = "service.log";

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LogConfig {
    pub level: LogLevel,
    pub format: LogFormat,

    /// None = only stdout
    /// Some(path) = stdout + rolling file logs
    pub dir: Option<PathBuf>,

    pub rotation: LogRotation,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: LogLevel::Info,
            format: LogFormat::Pretty,
            dir: Some(PathBuf::from("logs")),
            rotation: LogRotation::Daily,
        }
    }
}

impl Validatable for LogConfig {
    fn validate(&self) -> ValidationResult {
        Ok(())
    }
}

impl LogConfig {
    /// Initialize global tracing subscriber.
    ///
    /// The returned guard must be kept alive for the whole service lifetime.
    ///
    /// Example:
    ///
    /// ```ignore
    /// let log_guard = config.log.init()?;
    /// run_service().await?;
    /// drop(log_guard); // flush logs before exit
    /// ```
    pub fn init(&self) -> Result<LogGuard, ValidationError> {
        let mut guards = Vec::new();

        // stdout output
        let (stdout_writer, stdout_guard) = tracing_appender::non_blocking(std::io::stdout());
        guards.push(stdout_guard);

        let mut writer = BoxMakeWriter::new(stdout_writer);

        // optional file output
        if let Some(dir) = &self.dir {
            std::fs::create_dir_all(dir).map_err(|source| {
                ValidationError::rule_violation(ValidationReport::config().with_issue(
                    ValidationIssue::new("log.dir", "crate_dir_failed", format!("{source}")),
                ))
            })?;

            let file_appender = self.file_appender(dir);
            let (file_writer, file_guard) = tracing_appender::non_blocking(file_appender);

            guards.push(file_guard);

            // Tee stdout + file.
            writer = BoxMakeWriter::new(writer.and(file_writer));
        }

        let format = self.format;

        // When file logging is enabled, disable ANSI globally,
        // otherwise color escape codes will also be written into log files.
        let ansi = self.dir.is_none() && !matches!(format, LogFormat::Json);

        let builder = tracing_subscriber::fmt()
            .with_writer(writer)
            .with_max_level(self.level.as_level_filter())
            .with_ansi(ansi)
            .with_target(true)
            .with_thread_ids(true)
            .with_thread_names(true);

        match format {
            LogFormat::Pretty => builder.pretty().try_init().map_err(|source| {
                ValidationError::rule_violation(ValidationReport::config().with_issue(
                    ValidationIssue::new("log.format", "pretty_init_failed", format!("{source}")),
                ))
            }),
            LogFormat::Compact => builder.compact().try_init().map_err(|source| {
                ValidationError::rule_violation(ValidationReport::config().with_issue(
                    ValidationIssue::new("log.format", "compact_init_failed", format!("{source}")),
                ))
            }),
            LogFormat::Json => builder.json().try_init().map_err(|source| {
                ValidationError::rule_violation(ValidationReport::config().with_issue(
                    ValidationIssue::new("log.format", "json_init_failed", format!("{source}")),
                ))
            }),
        }?;

        Ok(LogGuard { _guards: guards })
    }

    fn file_appender(&self, dir: &Path) -> RollingFileAppender {
        match self.rotation {
            LogRotation::Never => rolling::never(dir, DEFAULT_LOG_FILE_NAME),
            LogRotation::Hourly => rolling::hourly(dir, DEFAULT_LOG_FILE_NAME),
            LogRotation::Daily => rolling::daily(dir, DEFAULT_LOG_FILE_NAME),
        }
    }
}

/// Keep this value alive during the whole service lifetime.
///
/// Dropping it at shutdown flushes non-blocking log buffers.
#[derive(Debug)]
pub struct LogGuard {
    _guards: Vec<WorkerGuard>,
}

impl LogGuard {
    /// Explicit shutdown hook.
    ///
    /// Consuming self triggers `WorkerGuard` drop and flushes buffered logs.
    pub fn shutdown(self) {}
}

#[derive(Debug, Default, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogLevel {
    Trace,
    Debug,
    #[default]
    Info,
    Warn,
    Error,
}

impl LogLevel {
    fn as_level_filter(self) -> LevelFilter {
        match self {
            LogLevel::Trace => LevelFilter::TRACE,
            LogLevel::Debug => LevelFilter::DEBUG,
            LogLevel::Info => LevelFilter::INFO,
            LogLevel::Warn => LevelFilter::WARN,
            LogLevel::Error => LevelFilter::ERROR,
        }
    }
}

#[derive(Debug, Default, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogFormat {
    #[default]
    Pretty,
    Compact,
    Json,
}

#[derive(Debug, Default, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogRotation {
    Never,
    Hourly,
    #[default]
    Daily,
}
