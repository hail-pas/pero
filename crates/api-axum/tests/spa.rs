use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
    response::IntoResponse,
    routing::get,
};
use tower::ServiceExt;

#[tokio::test]
async fn navigation_and_json_requests_share_authorization_and_preserve_cookies() {
    let directory = std::env::temp_dir().join(format!("pero-spa-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir_all(&directory).unwrap();
    std::fs::write(
        directory.join("index.html"),
        "<main>React application</main>",
    )
    .unwrap();
    let serve_dir = directory.clone();
    let page_dir = directory.clone();
    let page_calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let calls = page_calls.clone();
    let app = Router::new()
        .route(
            "/page",
            get(move || {
                calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                async { StatusCode::FORBIDDEN }
            }),
        )
        .route_layer(axum::middleware::from_fn(move |req, next| {
            let directory = page_dir.clone();
            async move { pero_api_axum::spa::serve_page(req, next, directory).await }
        }))
        .route(
            "/private",
            get(|| async {
                (
                    StatusCode::FORBIDDEN,
                    [("set-cookie", "csrf=token; HttpOnly")],
                    axum::Json(serde_json::json!({"view":"ForbiddenView"})),
                )
            }),
        )
        .route(
            "/static/assets/app-hash.js",
            get(|| async { "export default 1" }),
        )
        .route(
            "/login",
            get(|| async {
                axum::response::Redirect::to("https://issuer.test/oauth2/authorize").into_response()
            }),
        )
        .layer(axum::middleware::from_fn(move |req, next| {
            let directory = serve_dir.clone();
            async move { pero_api_axum::spa::serve(req, next, directory).await }
        }));
    let shell = app
        .clone()
        .oneshot(
            Request::get("/page")
                .header("accept", "text/html")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(shell.status(), StatusCode::OK);
    assert_eq!(shell.headers()["cache-control"], "no-store");
    assert_eq!(page_calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    let data = app
        .clone()
        .oneshot(
            Request::get("/page")
                .header("accept", "application/json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(data.status(), StatusCode::FORBIDDEN);
    assert_eq!(page_calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    let invalid_method = app
        .clone()
        .oneshot(
            Request::post("/page")
                .header("accept", "text/html")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(invalid_method.status(), StatusCode::METHOD_NOT_ALLOWED);
    let json = app
        .clone()
        .oneshot(
            Request::get("/private")
                .header("accept", "application/json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(json.status(), StatusCode::FORBIDDEN);
    assert_eq!(json.headers()["cache-control"], "no-store");
    assert!(
        String::from_utf8(to_bytes(json.into_body(), 1024).await.unwrap().to_vec())
            .unwrap()
            .contains("ForbiddenView")
    );
    let html = app
        .clone()
        .oneshot(
            Request::get("/private")
                .header("accept", "text/html")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(html.status(), StatusCode::FORBIDDEN);
    assert_eq!(html.headers()["set-cookie"], "csrf=token; HttpOnly");
    assert_eq!(html.headers()["content-type"], "text/html; charset=utf-8");
    assert!(
        String::from_utf8(to_bytes(html.into_body(), 1024).await.unwrap().to_vec())
            .unwrap()
            .contains("React application")
    );
    for (path, status, cache) in [
        (
            "/static/assets/app-hash.js",
            StatusCode::OK,
            "public, max-age=31536000, immutable",
        ),
        (
            "/static/assets/missing.js",
            StatusCode::NOT_FOUND,
            "no-store",
        ),
    ] {
        let response = app
            .clone()
            .oneshot(Request::get(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), status);
        assert_eq!(response.headers()["cache-control"], cache);
    }
    let redirect = app
        .oneshot(
            Request::get("/login")
                .header("accept", "application/json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let data: serde_json::Value =
        serde_json::from_slice(&to_bytes(redirect.into_body(), 1024).await.unwrap()).unwrap();
    assert_eq!(data["redirect"], "https://issuer.test/oauth2/authorize");
    std::fs::remove_dir_all(directory).unwrap();
}
