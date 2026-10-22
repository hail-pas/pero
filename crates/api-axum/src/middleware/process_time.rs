use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::Instant,
};

use axum::http::{HeaderValue, Request, Response, header::HeaderName};
use tower::{Layer, Service};

use crate::headers;

type ResponseFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;

const SERVER_TIMING_HEADER: HeaderName = HeaderName::from_static(headers::SERVER_TIMING);
const X_PROCESS_TIME_MS_HEADER: HeaderName = HeaderName::from_static(headers::X_PROCESS_TIME_MS);

pub fn process_time_layer() -> ProcessTimeLayer {
    ProcessTimeLayer
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ProcessTimeLayer;

impl<S> Layer<S> for ProcessTimeLayer {
    type Service = ProcessTimeService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ProcessTimeService { inner }
    }
}

#[derive(Debug, Clone)]
pub struct ProcessTimeService<S> {
    inner: S,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for ProcessTimeService<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Send + 'static,
    S::Future: Send + 'static,
    ReqBody: Send + 'static,
    ResBody: Send + 'static,
{
    type Response = Response<ResBody>;
    type Error = S::Error;
    type Future = ResponseFuture<Result<Self::Response, Self::Error>>;

    #[inline]
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<ReqBody>) -> Self::Future {
        let started_at = Instant::now();
        let future = self.inner.call(request);

        Box::pin(async move {
            let mut response = future.await?;

            let elapsed_ms = started_at.elapsed().as_secs_f64() * 1_000.0;

            insert_process_time_headers(response.headers_mut(), elapsed_ms);

            Ok(response)
        })
    }
}

#[inline]
fn insert_process_time_headers(headers: &mut axum::http::HeaderMap, elapsed_ms: f64) {
    let elapsed = format!("{elapsed_ms:.2}");

    let server_timing = format!("app;dur={elapsed}");

    // format! 生成的内容只包含 ASCII 数字、点号、分号和等号，
    // 理论上一定是合法 HeaderValue；这里仍保留 fallible 处理，避免运行时 panic。
    if let Ok(value) = HeaderValue::from_str(&server_timing) {
        headers.insert(SERVER_TIMING_HEADER, value);
    }

    if let Ok(value) = HeaderValue::from_str(&elapsed) {
        headers.insert(X_PROCESS_TIME_MS_HEADER, value);
    }
}
