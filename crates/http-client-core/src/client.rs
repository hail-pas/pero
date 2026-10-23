use async_trait::async_trait;
use http::{HeaderMap, StatusCode};
use pero_error::AppError;
use serde::de::DeserializeOwned;

pub type HttpClientResult<T> = Result<T, AppError>;

#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

impl HttpResponse {
    pub fn json<T: DeserializeOwned>(&self) -> HttpClientResult<T> {
        serde_json::from_slice(&self.body).map_err(|err| {
            AppError::json_dependency_failure(
                "http_client_json_decode_failed",
                "Failed to decode response body as JSON",
                err,
            )
        })
    }

    pub fn error_for_status(self) -> HttpClientResult<Self> {
        if self.status.is_success() {
            return Ok(self);
        }

        let status = self.status;
        let err = AppError::dependency_failure(
            "http_client_status_error",
            format!("Upstream returned HTTP {}", status.as_u16()),
        )
        .with_extension("upstream_status", status.as_u16());

        Err(err)
    }
}

#[async_trait]
pub trait HttpClient: Send + Sync {
    async fn send(&self, request: http::Request<Vec<u8>>) -> HttpClientResult<HttpResponse>;
}

/// A shared transport exposes only bounded request execution, not backend escape hatches.
pub type HttpClientHandle = std::sync::Arc<dyn HttpClient>;

/// Request-local opt-out for exchanges that consume a single-use credential.
/// Transports must not replay a request carrying this extension.
#[derive(Debug, Clone, Copy)]
pub struct NoRetry;

#[async_trait]
impl<T: HttpClient + ?Sized> HttpClient for &T {
    async fn send(&self, request: http::Request<Vec<u8>>) -> HttpClientResult<HttpResponse> {
        T::send(*self, request).await
    }
}

#[async_trait]
impl<T: HttpClient + ?Sized> HttpClient for std::sync::Arc<T> {
    async fn send(&self, request: http::Request<Vec<u8>>) -> HttpClientResult<HttpResponse> {
        self.as_ref().send(request).await
    }
}
