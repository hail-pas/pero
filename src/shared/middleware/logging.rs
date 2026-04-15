use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;
use std::time::Instant;
use crate::shared::middleware::request_id::RequestId;

pub async fn request_logging(req: Request, next: Next) -> Response {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let request_id = req.extensions().get::<RequestId>().map(|rid| rid.0.to_string()).unwrap_or_default();
    let start = Instant::now();

    let response = next.run(req).await;

    let elapsed = start.elapsed();
    let status = response.status().as_u16();

    tracing::info!(
        method = %method,
        uri = %uri,
        status = status,
        elapsed_ms = elapsed.as_millis() as u64,
        request_id = %request_id,
        "request completed"
    );

    response
}
