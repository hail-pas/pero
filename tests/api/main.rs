#[path = "../common/mod.rs"]
mod common;

use axum::http::StatusCode;
use common::*;
use http_body_util::BodyExt;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use pero::config::OidcConfig;
use pero::domain::app::models::UpdateAppRequest;
use pero::domain::oauth2::error::map_app_error;
use pero::infra::jwt::{JwtKeys, verify_token};
use pero::shared::error::AppError;
use pero::shared::patch::Patch;
use serde::Serialize;
use std::path::PathBuf;
use tower::ServiceExt;
use validator::{Validate, ValidationErrors};

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

#[test]
fn patch_validate_required_rejects_null_values() {
    let patch = Patch::<String>::Null;
    let mut errors = ValidationErrors::new();

    patch.validate_required("name", &mut errors, |_| Ok(()));

    assert!(errors.field_errors().contains_key("name"));
}

#[test]
fn app_update_rejects_null_for_required_patch_fields() {
    let req: UpdateAppRequest = serde_json::from_value(serde_json::json!({
        "name": null,
        "enabled": null
    }))
    .expect("valid app update json");

    assert!(req.validate().is_err());
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
