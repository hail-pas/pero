mod common;

use common::*;
use hyper::StatusCode;

#[tokio::test]
async fn create_policy() {
    let mut ta = build_app().await;
    let fx = ta.register_default_user().await;
    ta.grant_api_access(fx.user_id).await;

    let (status, body) = send_request(
        &mut ta.app,
        hyper::Method::POST,
        "/api/policies",
        Some(serde_json::json!({
            "name": unique_name("policy"),
            "effect": "allow",
            "priority": 10,
            "conditions": [
                { "condition_type": "action", "key": "method", "operator": "eq", "value": "GET" },
            ]
        })),
        Some(&fx.access_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "create policy failed: {body:?}");
    assert_eq!(body["data"]["effect"], "allow");
    ta.track_policy(body["data"]["id"].as_str().unwrap().parse().unwrap());
    ta.cleanup().await;
}

#[tokio::test]
async fn list_policies() {
    let mut ta = build_app().await;
    let fx = ta.register_default_user().await;
    ta.grant_api_access(fx.user_id).await;

    let (status, body) = send_request(
        &mut ta.app,
        hyper::Method::GET,
        "/api/policies?page=1&page_size=10",
        None,
        Some(&fx.access_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["data"]["items"].is_array());
    ta.cleanup().await;
}

#[tokio::test]
async fn get_update_delete_policy() {
    let mut ta = build_app().await;
    let fx = ta.register_default_user().await;
    ta.grant_api_access(fx.user_id).await;

    let policy_fx = ta.create_test_policy(&fx.access_token, "allow", 5).await;

    let (status, body) = send_request(
        &mut ta.app,
        hyper::Method::GET,
        &format!("/api/policies/{}", policy_fx.policy_id),
        None,
        Some(&fx.access_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["id"], policy_fx.policy_id.to_string());

    let (status, body) = send_request(
        &mut ta.app,
        hyper::Method::PUT,
        &format!("/api/policies/{}", policy_fx.policy_id),
        Some(serde_json::json!({
            "name": "updated_policy",
            "priority": 20,
        })),
        Some(&fx.access_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["priority"], 20);

    let (status, _) = send_request(
        &mut ta.app,
        hyper::Method::DELETE,
        &format!("/api/policies/{}", policy_fx.policy_id),
        None,
        Some(&fx.access_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    ta.cleanup().await;
}

#[tokio::test]
async fn assign_unassign_policy() {
    let mut ta = build_app().await;
    let fx = ta.register_default_user().await;
    ta.grant_api_access(fx.user_id).await;

    let policy_fx = ta.create_test_policy(&fx.access_token, "deny", 100).await;

    let (status, _) = send_request(
        &mut ta.app,
        hyper::Method::POST,
        &format!("/api/users/{}/policies/{}", fx.user_id, policy_fx.policy_id),
        None,
        Some(&fx.access_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = send_request(
        &mut ta.app,
        hyper::Method::GET,
        &format!("/api/users/{}/policies", fx.user_id),
        None,
        Some(&fx.access_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let items = body["data"].as_array().unwrap();
    assert!(items.iter().any(|p| p["id"] == policy_fx.policy_id.to_string()));

    let (status, _) = send_request(
        &mut ta.app,
        hyper::Method::DELETE,
        &format!("/api/users/{}/policies/{}", fx.user_id, policy_fx.policy_id),
        None,
        Some(&fx.access_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    ta.cleanup().await;
}

#[tokio::test]
async fn assign_nonexistent_policy() {
    let mut ta = build_app().await;
    let fx = ta.register_default_user().await;
    ta.grant_api_access(fx.user_id).await;

    let fake_policy_id = uuid::Uuid::new_v4();
    let (status, _) = send_request(
        &mut ta.app,
        hyper::Method::POST,
        &format!("/api/users/{}/policies/{fake_policy_id}", fx.user_id),
        None,
        Some(&fx.access_token),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    ta.cleanup().await;
}

#[tokio::test]
async fn policy_validation_invalid_effect() {
    let mut ta = build_app().await;
    let fx = ta.register_default_user().await;
    ta.grant_api_access(fx.user_id).await;

    let (status, _) = send_request(
        &mut ta.app,
        hyper::Method::POST,
        "/api/policies",
        Some(serde_json::json!({
            "name": unique_name("bad_pol"),
            "effect": "maybe",
            "priority": 1,
            "conditions": [],
        })),
        Some(&fx.access_token),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    ta.cleanup().await;
}

#[tokio::test]
async fn policy_validation_invalid_operator() {
    let mut ta = build_app().await;
    let fx = ta.register_default_user().await;
    ta.grant_api_access(fx.user_id).await;

    let (status, _) = send_request(
        &mut ta.app,
        hyper::Method::POST,
        "/api/policies",
        Some(serde_json::json!({
            "name": unique_name("bad_op"),
            "effect": "allow",
            "priority": 1,
            "conditions": [
                { "condition_type": "action", "key": "method", "operator": "invalid_op", "value": "GET" },
            ]
        })),
        Some(&fx.access_token),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    ta.cleanup().await;
}
