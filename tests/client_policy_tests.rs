mod common;

use common::*;
use hyper::StatusCode;

async fn setup_app_with_client(ta: &mut TestApp) -> (UserFixture, AppFixture, ClientFixture) {
    let fx = ta.register_default_user().await;
    ta.grant_api_access(fx.user_id).await;
    let app_fx = ta.create_test_app(&fx.access_token).await;
    let client_fx = ta
        .create_test_client(app_fx.app_id, &app_fx.code, &fx.access_token)
        .await;
    (fx, app_fx, client_fx)
}

#[tokio::test]
async fn client_create_policy() {
    let mut ta = build_app().await;
    let (_, _, client_fx) = setup_app_with_client(&mut ta).await;

    let (status, body) = send_basic_auth_request(
        &mut ta.app,
        hyper::Method::POST,
        "/api/client/policies",
        Some(serde_json::json!({
            "name": unique_name("cpol"),
            "effect": "allow",
            "priority": 100,
            "conditions": [],
        })),
        &client_fx.client_id_str,
        &client_fx.client_secret,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "client create policy failed: {body:?}"
    );
    assert_eq!(body["data"]["effect"], "allow");
    let policy_id: uuid::Uuid = body["data"]["id"].as_str().unwrap().parse().unwrap();
    ta.track_policy(policy_id);
    ta.cleanup().await;
}

#[tokio::test]
async fn client_create_policy_auto_scopes_app_id() {
    let mut ta = build_app().await;
    let (_, app_fx, client_fx) = setup_app_with_client(&mut ta).await;

    let (status, body) = send_basic_auth_request(
        &mut ta.app,
        hyper::Method::POST,
        "/api/client/policies",
        Some(serde_json::json!({
            "name": unique_name("scoped"),
            "effect": "allow",
            "priority": 50,
            "conditions": [],
        })),
        &client_fx.client_id_str,
        &client_fx.client_secret,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["app_id"], app_fx.app_id.to_string());
    let policy_id: uuid::Uuid = body["data"]["id"].as_str().unwrap().parse().unwrap();
    ta.track_policy(policy_id);
    ta.cleanup().await;
}

#[tokio::test]
async fn client_list_policies() {
    let mut ta = build_app().await;
    let (_, _, client_fx) = setup_app_with_client(&mut ta).await;

    let (status, _) = send_basic_auth_request(
        &mut ta.app,
        hyper::Method::POST,
        "/api/client/policies",
        Some(serde_json::json!({
            "name": unique_name("lpol"),
            "effect": "allow",
            "priority": 10,
            "conditions": [],
        })),
        &client_fx.client_id_str,
        &client_fx.client_secret,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = send_basic_auth_request(
        &mut ta.app,
        hyper::Method::GET,
        "/api/client/policies?page=1&page_size=10",
        None,
        &client_fx.client_id_str,
        &client_fx.client_secret,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["data"]["total"].as_i64().unwrap() >= 1);
    ta.cleanup().await;
}

#[tokio::test]
async fn client_get_update_delete_policy() {
    let mut ta = build_app().await;
    let (_, _, client_fx) = setup_app_with_client(&mut ta).await;

    let (status, body) = send_basic_auth_request(
        &mut ta.app,
        hyper::Method::POST,
        "/api/client/policies",
        Some(serde_json::json!({
            "name": unique_name("gud"),
            "effect": "allow",
            "priority": 10,
            "conditions": [],
        })),
        &client_fx.client_id_str,
        &client_fx.client_secret,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let policy_id = body["data"]["id"].as_str().unwrap();
    ta.track_policy(policy_id.parse().unwrap());

    let (status, body) = send_basic_auth_request(
        &mut ta.app,
        hyper::Method::GET,
        &format!("/api/client/policies/{policy_id}"),
        None,
        &client_fx.client_id_str,
        &client_fx.client_secret,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["id"], policy_id);

    let (status, body) = send_basic_auth_request(
        &mut ta.app,
        hyper::Method::PUT,
        &format!("/api/client/policies/{policy_id}"),
        Some(serde_json::json!({ "priority": 99 })),
        &client_fx.client_id_str,
        &client_fx.client_secret,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["priority"], 99);

    let (status, _) = send_basic_auth_request(
        &mut ta.app,
        hyper::Method::DELETE,
        &format!("/api/client/policies/{policy_id}"),
        None,
        &client_fx.client_id_str,
        &client_fx.client_secret,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    ta.cleanup().await;
}

#[tokio::test]
async fn client_cannot_access_other_app_policy() {
    let mut ta = build_app().await;
    let admin_fx = ta.register_default_user().await;
    ta.grant_api_access(admin_fx.user_id).await;

    let admin_policy = ta
        .create_test_policy(&admin_fx.access_token, "allow", 10)
        .await;

    let (_, _, client_fx) = setup_app_with_client(&mut ta).await;

    let (status, _) = send_basic_auth_request(
        &mut ta.app,
        hyper::Method::GET,
        &format!("/api/client/policies/{}", admin_policy.policy_id),
        None,
        &client_fx.client_id_str,
        &client_fx.client_secret,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    ta.cleanup().await;
}

#[tokio::test]
async fn client_assign_unassign_policy_to_user() {
    let mut ta = build_app().await;
    let (_, _, client_fx) = setup_app_with_client(&mut ta).await;

    let target_user = ta.register_default_user().await;

    let (status, body) = send_basic_auth_request(
        &mut ta.app,
        hyper::Method::POST,
        "/api/client/policies",
        Some(serde_json::json!({
            "name": unique_name("assign"),
            "effect": "allow",
            "priority": 100,
            "conditions": [],
        })),
        &client_fx.client_id_str,
        &client_fx.client_secret,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let policy_id = body["data"]["id"].as_str().unwrap();
    ta.track_policy(policy_id.parse().unwrap());

    let (status, _) = send_basic_auth_request(
        &mut ta.app,
        hyper::Method::POST,
        &format!(
            "/api/client/users/{}/policies/{}",
            target_user.user_id, policy_id
        ),
        None,
        &client_fx.client_id_str,
        &client_fx.client_secret,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = send_basic_auth_request(
        &mut ta.app,
        hyper::Method::GET,
        &format!("/api/client/users/{}/policies", target_user.user_id),
        None,
        &client_fx.client_id_str,
        &client_fx.client_secret,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let items = body["data"].as_array().unwrap();
    assert!(items.iter().any(|p| p["id"] == policy_id));

    let (status, _) = send_basic_auth_request(
        &mut ta.app,
        hyper::Method::DELETE,
        &format!(
            "/api/client/users/{}/policies/{}",
            target_user.user_id, policy_id
        ),
        None,
        &client_fx.client_id_str,
        &client_fx.client_secret,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    ta.cleanup().await;
}

#[tokio::test]
async fn client_wrong_credentials_rejected() {
    let mut ta = build_app().await;
    let (_, _, client_fx) = setup_app_with_client(&mut ta).await;

    let (status, _) = send_basic_auth_request(
        &mut ta.app,
        hyper::Method::GET,
        "/api/client/policies?page=1&page_size=10",
        None,
        &client_fx.client_id_str,
        "wrong_secret",
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    ta.cleanup().await;
}

#[tokio::test]
async fn client_no_auth_rejected() {
    let mut ta = build_app().await;

    let (status, _) = send_request(
        &mut ta.app,
        hyper::Method::GET,
        "/api/client/policies?page=1&page_size=10",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    ta.cleanup().await;
}
