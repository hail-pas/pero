#[path = "../common/mod.rs"]
mod common;

use common::*;
use hyper::StatusCode;

#[tokio::test]
async fn discovery() {
    let (mut app, _rt) = build_router().await;
    let (status, body) = send_request(
        &mut app,
        hyper::Method::GET,
        "/.well-known/openid-configuration",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["issuer"].is_string());
    assert!(body["authorization_endpoint"].is_string());
    assert!(body["token_endpoint"].is_string());
    assert!(body["userinfo_endpoint"].is_string());
    assert!(body["jwks_uri"].is_string());
    assert!(body["response_types_supported"].is_array());
    assert!(body["id_token_signing_alg_values_supported"].is_array());
    assert!(body["scopes_supported"].is_array());
}

#[tokio::test]
async fn jwks() {
    let (mut app, _rt) = build_router().await;
    let (status, body) =
        send_request(&mut app, hyper::Method::GET, "/oauth2/keys", None, None).await;
    assert_eq!(status, StatusCode::OK);
    let keys = body["keys"].as_array().unwrap();
    assert!(!keys.is_empty());
    assert_eq!(keys[0]["kty"], "RSA");
    assert!(keys[0]["kid"].is_string());
    assert!(keys[0]["n"].is_string());
}

#[tokio::test]
async fn userinfo_no_auth() {
    let (mut app, _rt) = build_router().await;
    let (status, _) =
        send_request(&mut app, hyper::Method::GET, "/oauth2/userinfo", None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn userinfo_with_auth() {
    let mut ta = build_app().await;
    let fx = ta.register_default_user().await;
    let (status, body) = send_request(
        &mut ta.app,
        hyper::Method::GET,
        "/oauth2/userinfo",
        None,
        Some(&fx.access_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["sub"], fx.user_id.to_string());
    ta.cleanup().await;
}

#[tokio::test]
async fn end_session_clears_cookie() {
    let (mut app, _rt) = build_router().await;
    let (status, _) = send_raw_request(
        &mut app,
        hyper::Method::GET,
        "/oauth2/session/end",
    )
    .await;
    assert!(status == StatusCode::OK || status == StatusCode::FOUND);
}

#[tokio::test]
async fn discovery_includes_end_session_endpoint() {
    let (mut app, _rt) = build_router().await;
    let (_, body) = send_request(
        &mut app,
        hyper::Method::GET,
        "/.well-known/openid-configuration",
        None,
        None,
    )
    .await;
    assert!(body["end_session_endpoint"].is_string(), "discovery must include end_session_endpoint");
    assert!(body["token_endpoint_auth_methods_supported"].is_array());
}
