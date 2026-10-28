//! Content negotiation for the separately built React application.
use axum::{
    body::Body,
    http::{Request, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::path::PathBuf;

fn accepts(req: &Request<Body>, mime: &str) -> bool {
    req.headers()
        .get(header::ACCEPT)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.contains(mime))
}

fn is_navigation(req: &Request<Body>) -> bool {
    req.method() == axum::http::Method::GET
        && accepts(req, "text/html")
        && !accepts(req, "application/json")
}

async fn index(directory: PathBuf) -> Response {
    let mut response = match tokio::fs::read(directory.join("index.html")).await {
        Ok(html) => axum::response::Html(html).into_response(),
        Err(error) => {
            tracing::error!(%error, "Build the frontend before starting the service");
            (
                axum::http::StatusCode::SERVICE_UNAVAILABLE,
                "Frontend build missing",
            )
                .into_response()
        }
    };
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    response
}

/// Attach only to page routes. Their JSON requests still run all authentication and handlers.
pub async fn serve_page(req: Request<Body>, next: Next, directory: PathBuf) -> Response {
    if is_navigation(&req) {
        index(directory).await
    } else {
        next.run(req).await
    }
}

pub async fn serve(req: Request<Body>, next: Next, directory: PathBuf) -> Response {
    let json = accepts(&req, "application/json");
    let navigation = is_navigation(&req);
    let is_protocol = req.uri().path().starts_with("/api/")
        || req.uri().path().starts_with("/.well-known/")
        || req.uri().path() == "/ready";
    let is_asset = req.uri().path().starts_with("/static/assets/");
    let mut response = next.run(req).await;
    if json && response.status().is_redirection() {
        if let Some(location) = response
            .headers()
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
        {
            let cookies: Vec<_> = response
                .headers()
                .get_all(header::SET_COOKIE)
                .iter()
                .cloned()
                .collect();
            response = axum::Json(serde_json::json!({"redirect": location})).into_response();
            for cookie in cookies {
                response.headers_mut().append(header::SET_COOKIE, cookie);
            }
        }
    } else if navigation
        && !is_protocol
        && response
            .headers()
            .get(header::CONTENT_TYPE)
            .is_some_and(|v| v == "application/json")
    {
        // Protocol-driven views (e.g. logout confirmation) must execute their handler first.
        let html = index(directory).await;
        if !html.status().is_success() {
            return html;
        }
        *response.body_mut() = html.into_body();
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            header::HeaderValue::from_static("text/html; charset=utf-8"),
        );
        response.headers_mut().remove(header::CONTENT_LENGTH);
    }
    if !is_protocol {
        let cache = if is_asset && response.status().is_success() {
            "public, max-age=31536000, immutable"
        } else {
            "no-store"
        };
        response.headers_mut().insert(
            header::CACHE_CONTROL,
            header::HeaderValue::from_static(cache),
        );
    }
    response
}
