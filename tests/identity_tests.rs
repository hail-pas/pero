mod common;

use common::*;
use hyper::StatusCode;

#[tokio::test]
async fn register_success() {
    let mut ta = build_app().await;
    let fx = ta.register_default_user().await;
    assert!(!fx.access_token.is_empty());
    assert!(!fx.refresh_token.is_empty());
    ta.cleanup().await;
}

#[tokio::test]
async fn register_duplicate_username() {
    let mut ta = build_app().await;
    let username = unique_name("dupu");
    let email1 = unique_email("dupu1");
    let email2 = unique_email("dupu2");
    let _fx = ta.register_user(&username, &email1, "password123").await;

    let (status, _) = send_request(
        &mut ta.app,
        hyper::Method::POST,
        "/api/identity/register",
        Some(serde_json::json!({
            "username": username,
            "email": email2,
            "password": "password123",
        })),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    ta.cleanup().await;
}

#[tokio::test]
async fn register_duplicate_email() {
    let mut ta = build_app().await;
    let email = unique_email("dupe");
    let username1 = unique_name("dupe1");
    let username2 = unique_name("dupe2");
    let _ = ta.register_user(&username1, &email, "password123").await;

    let (status, _) = send_request(
        &mut ta.app,
        hyper::Method::POST,
        "/api/identity/register",
        Some(serde_json::json!({
            "username": username2,
            "email": email,
            "password": "password123",
        })),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    ta.cleanup().await;
}

#[tokio::test]
async fn register_short_password() {
    let (mut app, _rt) = build_router().await;
    let (status, _) = send_request(
        &mut app,
        hyper::Method::POST,
        "/api/identity/register",
        Some(serde_json::json!({
            "username": unique_name("shortpw"),
            "email": unique_email("shortpw"),
            "password": "abc",
        })),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn login_success() {
    let mut ta = build_app().await;
    let fx = ta.register_default_user().await;
    let token = login_user_inner(&mut ta.app, &fx.username, "password123").await;
    assert!(!token.is_empty());
    ta.cleanup().await;
}

#[tokio::test]
async fn login_wrong_password() {
    let mut ta = build_app().await;
    let fx = ta.register_default_user().await;
    let (status, _) = send_request(
        &mut ta.app,
        hyper::Method::POST,
        "/api/identity/login",
        Some(serde_json::json!({
            "identifier": fx.username,
            "password": "wrongpassword1",
        })),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    ta.cleanup().await;
}

#[tokio::test]
async fn login_nonexistent_user() {
    let (mut app, _rt) = build_router().await;
    let (status, _) = send_request(
        &mut app,
        hyper::Method::POST,
        "/api/identity/login",
        Some(serde_json::json!({
            "identifier": "nonexistent_user_12345",
            "password": "password123",
        })),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn refresh_token_success() {
    let mut ta = build_app().await;
    let fx = ta.register_default_user().await;
    let (status, body) = send_request(
        &mut ta.app,
        hyper::Method::POST,
        "/auth/refresh",
        Some(serde_json::json!({
            "refresh_token": fx.refresh_token,
        })),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["data"]["access_token"].is_string());
    assert!(body["data"]["refresh_token"].is_string());
    ta.cleanup().await;
}

#[tokio::test]
async fn refresh_token_invalid() {
    let (mut app, _rt) = build_router().await;
    let (status, _) = send_request(
        &mut app,
        hyper::Method::POST,
        "/auth/refresh",
        Some(serde_json::json!({
            "refresh_token": "invalid_token",
        })),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn get_me() {
    let mut ta = build_app().await;
    let fx = ta.register_default_user().await;
    let (status, body) = send_request(
        &mut ta.app,
        hyper::Method::GET,
        "/api/users/me",
        None,
        Some(&fx.access_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["username"], fx.username);
    assert_eq!(body["data"]["email"], fx.email);
    ta.cleanup().await;
}

#[tokio::test]
async fn update_me() {
    let mut ta = build_app().await;
    let fx = ta.register_default_user().await;
    let (status, body) = send_request(
        &mut ta.app,
        hyper::Method::PUT,
        "/api/users/me",
        Some(serde_json::json!({
            "nickname": "Test Nickname",
        })),
        Some(&fx.access_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["nickname"], "Test Nickname");
    ta.cleanup().await;
}

#[tokio::test]
async fn update_me_patch_set_then_clear() {
    let mut ta = build_app().await;
    let fx = ta.register_default_user().await;

    let (status, body) = send_request(
        &mut ta.app,
        hyper::Method::PUT,
        "/api/users/me",
        Some(serde_json::json!({
            "nickname": "Nick1",
            "phone": "+1234567890",
        })),
        Some(&fx.access_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["nickname"], "Nick1");
    assert_eq!(body["data"]["phone"], "+1234567890");

    let (status, body) = send_request(
        &mut ta.app,
        hyper::Method::PUT,
        "/api/users/me",
        Some(serde_json::json!({
            "nickname": null,
            "phone": null,
        })),
        Some(&fx.access_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["data"]["nickname"].is_null());
    assert!(body["data"]["phone"].is_null());

    let (status, body) = send_request(
        &mut ta.app,
        hyper::Method::PUT,
        "/api/users/me",
        Some(serde_json::json!({
            "avatar_url": "https://example.com/avatar.png",
        })),
        Some(&fx.access_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["avatar_url"], "https://example.com/avatar.png");
    assert!(
        body["data"]["nickname"].is_null(),
        "nickname should stay null"
    );
    assert!(body["data"]["phone"].is_null(), "phone should stay null");

    ta.cleanup().await;
}

#[tokio::test]
async fn update_user_patch_tristate() {
    let mut ta = build_app().await;
    let fx = ta.register_default_user().await;
    ta.grant_api_access(fx.user_id).await;

    let (status, body) = send_request(
        &mut ta.app,
        hyper::Method::PUT,
        &format!("/api/users/{}", fx.user_id),
        Some(serde_json::json!({
            "nickname": "Admin Nick",
            "phone": "+1111111111",
            "status": 1,
        })),
        Some(&fx.access_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["nickname"], "Admin Nick");
    assert_eq!(body["data"]["phone"], "+1111111111");
    assert_eq!(body["data"]["status"], 1);

    let (status, body) = send_request(
        &mut ta.app,
        hyper::Method::PUT,
        &format!("/api/users/{}", fx.user_id),
        Some(serde_json::json!({
            "nickname": null,
            "status": 0,
        })),
        Some(&fx.access_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body["data"]["nickname"].is_null(),
        "nickname should be cleared"
    );
    assert_eq!(
        body["data"]["phone"], "+1111111111",
        "phone should be unchanged"
    );
    assert_eq!(body["data"]["status"], 0);

    ta.cleanup().await;
}

#[tokio::test]
async fn change_password() {
    let mut ta = build_app().await;
    let fx = ta
        .register_user(&unique_name("chpw"), &unique_email("chpw"), "oldpassword1")
        .await;

    let token = login_user_inner(&mut ta.app, &fx.username, "oldpassword1").await;

    let (status, _) = send_request(
        &mut ta.app,
        hyper::Method::PUT,
        "/api/identity/password/change",
        Some(serde_json::json!({
            "old_password": "oldpassword1",
            "new_password": "newpassword1",
        })),
        Some(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let token2 = login_user_inner(&mut ta.app, &fx.username, "newpassword1").await;
    assert!(!token2.is_empty());
    ta.cleanup().await;
}

#[tokio::test]
async fn change_password_wrong_old() {
    let mut ta = build_app().await;
    let fx = ta.register_default_user().await;
    let (status, _) = send_request(
        &mut ta.app,
        hyper::Method::PUT,
        "/api/identity/password/change",
        Some(serde_json::json!({
            "old_password": "wrongpassword1",
            "new_password": "newpassword1",
        })),
        Some(&fx.access_token),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    ta.cleanup().await;
}

#[tokio::test]
async fn list_set_attributes() {
    let mut ta = build_app().await;
    let fx = ta.register_default_user().await;
    ta.grant_api_access(fx.user_id).await;

    let (status, _) = send_request(
        &mut ta.app,
        hyper::Method::PUT,
        &format!("/api/users/{}/attributes", fx.user_id),
        Some(serde_json::json!({
            "attributes": [
                { "key": "role", "value": "admin" },
                { "key": "department", "value": "engineering" },
            ]
        })),
        Some(&fx.access_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = send_request(
        &mut ta.app,
        hyper::Method::GET,
        &format!("/api/users/{}/attributes", fx.user_id),
        None,
        Some(&fx.access_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let attrs = body["data"].as_array().unwrap();
    assert!(attrs.len() >= 2);
    ta.cleanup().await;
}

#[tokio::test]
async fn unauth_without_token() {
    let (mut app, _rt) = build_router().await;
    let (status, _) = send_request(&mut app, hyper::Method::GET, "/api/users/me", None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}
