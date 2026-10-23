pub const X_REQUEST_ID: &str = "x-request-id";
pub const X_PROCESS_TIME_MS: &str = "x-process-time-ms";
pub const SERVER_TIMING: &str = "server-timing";

use axum::body::Body;
use axum::http::{HeaderName, HeaderValue, Request};
use axum::middleware::Next;
use axum::response::Response;

pub static DEFAULT_SECURITY_HEADERS: &[(&str, &str)] = &[
    ("x-content-type-options", "nosniff"),
    ("x-frame-options", "DENY"),
    ("referrer-policy", "strict-origin-when-cross-origin"),
    (
        "content-security-policy",
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'",
    ),
    (
        "permissions-policy",
        "camera=(), microphone=(), geolocation=()",
    ),
];

pub async fn security_headers(req: Request<Body>, next: Next) -> Response {
    let mut response = next.run(req).await;
    apply_security_headers(&mut response, DEFAULT_SECURITY_HEADERS);
    response
}

pub fn apply_security_headers(
    response: &mut Response,
    headers_to_apply: &[(&'static str, &'static str)],
) {
    let headers = response.headers_mut();
    for (name, value) in headers_to_apply {
        headers.insert(
            HeaderName::from_static(name),
            HeaderValue::from_static(value),
        );
    }
}
