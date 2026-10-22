use pero_config::blocks::{LogConfig, LogLevel};
use tower::Layer;
use tower_http::trace::{
    DefaultOnBodyChunk, DefaultOnFailure, DefaultOnRequest, DefaultOnResponse, HttpMakeClassifier,
    MakeSpan, TraceLayer,
};

type TowerTraceLayer = TraceLayer<
    HttpMakeClassifier,
    SanitizedMakeSpan,
    DefaultOnRequest,
    DefaultOnResponse,
    DefaultOnBodyChunk,
    (),
    DefaultOnFailure,
>;

pub fn tracing_layer(config: LogConfig) -> TracingMiddleware {
    TracingMiddleware::new(config)
}

#[derive(Debug, Clone)]
pub struct TracingMiddleware {
    inner: TowerTraceLayer,
}

impl TracingMiddleware {
    pub fn new(config: LogConfig) -> Self {
        let level = trace_level(&config);
        let inner = TraceLayer::new_for_http()
            .make_span_with(SanitizedMakeSpan { level })
            .on_request(DefaultOnRequest::new().level(level))
            .on_response(DefaultOnResponse::new().level(level))
            .on_eos(())
            .on_failure(DefaultOnFailure::new().level(::tracing::Level::ERROR));

        Self { inner }
    }
}

impl<S> Layer<S> for TracingMiddleware
where
    TowerTraceLayer: Layer<S>,
{
    type Service = <TowerTraceLayer as Layer<S>>::Service;

    fn layer(&self, inner: S) -> Self::Service {
        self.inner.layer(inner)
    }
}

fn trace_level(config: &LogConfig) -> ::tracing::Level {
    match config.level {
        LogLevel::Trace => ::tracing::Level::TRACE,
        LogLevel::Debug => ::tracing::Level::DEBUG,
        LogLevel::Info | LogLevel::Warn | LogLevel::Error => ::tracing::Level::INFO,
    }
}

/// OAuth callback and recovery credentials must never be recorded in request spans.
#[derive(Debug, Clone)]
pub struct SanitizedMakeSpan {
    level: ::tracing::Level,
}

impl<B> MakeSpan<B> for SanitizedMakeSpan {
    fn make_span(&mut self, request: &axum::http::Request<B>) -> ::tracing::Span {
        macro_rules! span {
            ($level:expr) => { ::tracing::span!($level, "request", method = %request.method(), path = request.uri().path(), version = ?request.version()) };
        }
        match self.level {
            ::tracing::Level::TRACE => span!(::tracing::Level::TRACE),
            ::tracing::Level::DEBUG => span!(::tracing::Level::DEBUG),
            _ => span!(::tracing::Level::INFO),
        }
    }
}
