mod common;

use common::*;
use hyper::StatusCode;

#[tokio::test]
async fn health_check() {
    let (mut app, _rt) = build_router().await;
    let (status, body) = send_request(&mut app, hyper::Method::GET, "/health", None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["code"], 0);
    assert_eq!(body["data"]["status"], "ok");
}

#[tokio::test]
async fn openapi_json() {
    let (mut app, _rt) = build_router().await;
    let (status, body) =
        send_request(&mut app, hyper::Method::GET, "/openapi.json", None, None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["openapi"].is_string());
    assert!(body["paths"].is_object());
    assert!(body["components"].is_object());
    assert!(body["info"]["title"].as_str().unwrap().contains("Pero"));
}

#[tokio::test]
async fn swagger_ui_assets() {
    use tower::ServiceExt;
    let (app, _rt) = build_router().await;
    let req = hyper::Request::builder()
        .method(hyper::Method::GET)
        .uri("/docs/swagger-ui-bundle.js")
        .body(axum::body::Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn not_found() {
    let (mut app, _rt) = build_router().await;
    let (status, _) = send_request(&mut app, hyper::Method::GET, "/nonexistent", None, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
