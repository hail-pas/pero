use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use pero_cache_redis::RedisCacheStore;
use pero_http_client_reqwest::ReqwestHttpClient;
use tower::ServiceExt;
use user_center::{config::AppConfig, state::app::AppState};

#[tokio::test]
async fn dependency_outage_preserves_liveness_and_probe_json() {
    // Reserve a local port without a protocol server to exercise the connection timeout.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let config: AppConfig = serde_json::from_value(serde_json::json!({
        "database":{"url":"postgres://unused:secret@127.0.0.1/unused","encrypt_key":"test-key"},
        "redis":{"url":format!("redis://{}", listener.local_addr().unwrap()),"connect_timeout_secs":1,"command_timeout_secs":1},
        "sso":{"cookie_signing_secret":"test-only-cookie-secret-long-enough"}
    })).unwrap();
    let cache = RedisCacheStore::from_config(&config.redis).unwrap();
    let http = ReqwestHttpClient::from_config(&config.http_config).unwrap();
    let state = AppState::new(config, Default::default(), cache, http);
    let app = user_center::router::build(state);
    for path in ["/health", "/api/health", "/ready", "/api/ready"] {
        let ready = path.ends_with("ready");
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(path)
                    .header(
                        "accept",
                        if ready {
                            "text/html"
                        } else {
                            "application/json"
                        },
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            if ready {
                StatusCode::SERVICE_UNAVAILABLE
            } else {
                StatusCode::OK
            }
        );
        assert_eq!(response.headers()["content-type"], "application/json");
        if ready {
            assert_eq!(response.headers()["cache-control"], "no-store");
        }
        let bytes = to_bytes(response.into_body(), 4096).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["code"], if ready { 503 } else { 0 });
        if ready {
            assert_eq!(
                body["data"]["dependencies"],
                serde_json::json!({"database":false,"redis":false})
            );
            assert_eq!(body["data"]["status"], "unavailable");
        } else {
            assert_eq!(body["data"]["status"], "ok");
        }
        assert!(!body.to_string().contains("secret"));
    }
}
