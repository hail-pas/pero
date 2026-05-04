#[path = "../common/mod.rs"]
mod common;

use axum::http::{Method, StatusCode};
use common::{TestApp, json_request};

#[tokio::test]
async fn memory_api_health_and_openapi_are_available() {
    let app = TestApp::new();

    let (health_status, health_body) =
        json_request(app.app.clone(), Method::GET, "/health", None, None).await;
    assert_eq!(health_status, StatusCode::OK);
    assert_eq!(health_body["data"]["status"], "ok");

    let (openapi_status, openapi_body) =
        json_request(app.app, Method::GET, "/openapi.json", None, None).await;
    assert_eq!(openapi_status, StatusCode::OK);
    assert!(openapi_body["paths"].is_object());
}

#[tokio::test]
async fn memory_public_pages_and_protocol_endpoints_are_fast_and_stateless() {
    let app = TestApp::new();
    let checks = [
        (Method::GET, "/.well-known/openid-configuration"),
        (Method::GET, "/oauth2/keys"),
        (Method::GET, "/oauth2/session/end"),
        (Method::GET, "/sso/error?code=access_denied"),
        (Method::GET, "/sso/login?error=session_expired"),
        (Method::GET, "/sso/register"),
        (Method::GET, "/sso/forgot-password"),
        (Method::GET, "/sso/reset-password?token=missing"),
        (Method::GET, "/sso/verify-email?token=missing"),
        (Method::GET, "/account/login"),
        (Method::GET, "/account/profile"),
        (
            Method::GET,
            "/oauth2/authorize?client_id=missing&redirect_uri=https%3A%2F%2Fapp.example.test%2Fcallback&response_type=code&code_challenge=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&code_challenge_method=S256",
        ),
    ];

    for (method, path) in checks {
        let (status, body) = json_request(app.app.clone(), method, path, None, None).await;
        assert!(
            status.is_success()
                || status.is_redirection()
                || status == StatusCode::BAD_REQUEST
                || status == StatusCode::UNAUTHORIZED
                || status == StatusCode::NOT_FOUND,
            "{path} returned {status}: {body:?}"
        );
    }
}
