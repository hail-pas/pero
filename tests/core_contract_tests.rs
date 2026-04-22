mod common;

use axum::http::StatusCode;
use http_body_util::BodyExt;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use pero::config::OidcConfig;
use pero::domains::oauth2::error::map_app_error;
use pero::shared::error::AppError;
use pero::shared::jwt::{JwtKeys, verify_token};
use pero::shared::middleware::rate_limit::RateLimiter;
use serde::Serialize;
use std::path::PathBuf;

#[derive(Debug, Serialize)]
struct AudTestClaims {
    sub: String,
    iss: String,
    aud: Vec<String>,
    roles: Vec<String>,
    exp: i64,
    iat: i64,
    scope: Option<String>,
}

fn load_test_keys() -> JwtKeys {
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    JwtKeys::load(&OidcConfig {
        issuer: "https://auth.example.com".to_string(),
        private_key_path: repo_root
            .join("config/keys/private.pem")
            .display()
            .to_string(),
        public_key_path: repo_root
            .join("config/keys/public.pem")
            .display()
            .to_string(),
        key_id: "test-key".to_string(),
    })
    .expect("failed to load test jwt keys")
}

#[test]
fn sqlx_row_not_found_maps_to_not_found() {
    let err = AppError::from(sqlx::Error::RowNotFound);
    assert!(matches!(err, AppError::NotFound(_)));
}

#[tokio::test]
async fn oauth2_validation_errors_map_to_invalid_request() {
    let response = map_app_error(AppError::Validation("missing field".into()));
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("failed to read body")
        .to_bytes();
    let body: serde_json::Value =
        serde_json::from_slice(&bytes).expect("failed to parse response body");

    assert_eq!(body["error"], "invalid_request");
}

#[test]
fn verify_token_rejects_unexpected_audience() {
    let keys = load_test_keys();
    let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let private_pem = std::fs::read_to_string(repo_root.join("config/keys/private.pem"))
        .expect("failed to read private key");
    let encoding_key =
        EncodingKey::from_rsa_pem(private_pem.as_bytes()).expect("failed to load encoding key");

    let now = chrono::Utc::now().timestamp();
    let claims = AudTestClaims {
        sub: "00000000-0000-0000-0000-000000000001".to_string(),
        iss: "https://auth.example.com".to_string(),
        aud: vec!["unexpected-audience".to_string()],
        roles: vec!["user".to_string()],
        exp: now + 300,
        iat: now,
        scope: None,
    };

    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(keys.key_id.clone());
    let token = encode(&header, &claims, &encoding_key).expect("failed to encode token");

    let result = verify_token(&token, &keys);
    assert!(matches!(result, Err(AppError::Unauthorized)));
}

#[tokio::test]
async fn rate_limiter_enforces_burst_capacity() {
    let limiter = RateLimiter::new(1, 1);

    assert!(limiter.try_acquire().await);
    assert!(!limiter.try_acquire().await);

    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;

    assert!(limiter.try_acquire().await);
}
