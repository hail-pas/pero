use crate::shared::constants::headers::X_PROCESS_TIME;
use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;
use std::time::Instant;

pub async fn response_time_middleware(req: Request, next: Next) -> Response {
    let start = Instant::now();
    let mut response = next.run(req).await;
    let elapsed_ms = start.elapsed().as_millis();

    let headers = response.headers_mut();
    headers.insert(
        axum::http::HeaderName::from_static(X_PROCESS_TIME),
        axum::http::HeaderValue::from(elapsed_ms as u64),
    );

    response
}
