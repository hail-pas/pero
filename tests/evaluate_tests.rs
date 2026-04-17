mod common;

use common::*;
use hyper::StatusCode;

#[tokio::test]
async fn evaluate_allowed_by_user_policy() {
    let mut ta = build_app().await;
    let fx = ta.register_default_user().await;
    ta.grant_api_access(fx.user_id).await;

    let app_fx = ta.create_test_app(&fx.access_token).await;

    let policy_name = unique_name("eval-allow");
    let (status, body) = send_request(
        &mut ta.app,
        hyper::Method::POST,
        "/api/policies",
        Some(serde_json::json!({
            "name": policy_name,
            "effect": "allow",
            "priority": 100,
            "app_id": app_fx.app_id.to_string(),
            "conditions": [
                {"condition_type": "resource", "key": "path", "operator": "wildcard", "value": "/test/**"},
                {"condition_type": "action", "key": "method", "operator": "in", "value": "GET"},
            ],
        })),
        Some(&fx.access_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "create policy failed: {body:?}");
    let policy_id: uuid::Uuid = body["data"]["id"].as_str().unwrap().parse().unwrap();
    ta.track_policy(policy_id);

    send_request(
        &mut ta.app,
        hyper::Method::POST,
        &format!("/api/users/{}/policies/{}", fx.user_id, policy_id),
        None,
        Some(&fx.access_token),
    )
    .await;

    let (status, body) = send_request(
        &mut ta.app,
        hyper::Method::POST,
        "/api/abac/evaluate",
        Some(serde_json::json!({
            "resource": "/test/data",
            "action": "GET",
            "app_id": app_fx.app_id.to_string(),
        })),
        Some(&fx.access_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "evaluate failed: {body:?}");
    assert_eq!(body["data"]["allowed"], true);
    assert_eq!(body["data"]["effect"], "allow");
    ta.cleanup().await;
}

#[tokio::test]
async fn evaluate_denied_no_policy() {
    let mut ta = build_app().await;
    let fx = ta.register_default_user().await;

    let app_fx = ta.create_test_app_direct().await;

    let (status, body) = send_request(
        &mut ta.app,
        hyper::Method::POST,
        "/api/abac/evaluate",
        Some(serde_json::json!({
            "resource": "/test/nonexistent",
            "action": "GET",
            "app_id": app_fx.app_id.to_string(),
        })),
        Some(&fx.access_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["allowed"], false);
    assert_eq!(body["data"]["effect"], "deny");
    ta.cleanup().await;
}

#[tokio::test]
async fn evaluate_denied_by_higher_priority_deny() {
    let mut ta = build_app().await;
    let fx = ta.register_default_user().await;
    ta.grant_api_access(fx.user_id).await;

    let app_fx = ta.create_test_app(&fx.access_token).await;

    let allow_name = unique_name("eval-allow");
    let (status, body) = send_request(
        &mut ta.app,
        hyper::Method::POST,
        "/api/policies",
        Some(serde_json::json!({
            "name": allow_name,
            "effect": "allow",
            "priority": 50,
            "app_id": app_fx.app_id.to_string(),
            "conditions": [
                {"condition_type": "resource", "key": "path", "operator": "wildcard", "value": "/test/**"},
            ],
        })),
        Some(&fx.access_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "allow policy failed: {body:?}");
    let allow_id: uuid::Uuid = body["data"]["id"].as_str().unwrap().parse().unwrap();
    ta.track_policy(allow_id);

    let deny_name = unique_name("eval-deny");
    let (status, body) = send_request(
        &mut ta.app,
        hyper::Method::POST,
        "/api/policies",
        Some(serde_json::json!({
            "name": deny_name,
            "effect": "deny",
            "priority": 100,
            "app_id": app_fx.app_id.to_string(),
            "conditions": [
                {"condition_type": "resource", "key": "path", "operator": "wildcard", "value": "/test/**"},
            ],
        })),
        Some(&fx.access_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "deny policy failed: {body:?}");
    let deny_id: uuid::Uuid = body["data"]["id"].as_str().unwrap().parse().unwrap();
    ta.track_policy(deny_id);

    send_request(
        &mut ta.app,
        hyper::Method::POST,
        &format!("/api/users/{}/policies/{}", fx.user_id, allow_id),
        None,
        Some(&fx.access_token),
    )
    .await;
    send_request(
        &mut ta.app,
        hyper::Method::POST,
        &format!("/api/users/{}/policies/{}", fx.user_id, deny_id),
        None,
        Some(&fx.access_token),
    )
    .await;

    let (status, body) = send_request(
        &mut ta.app,
        hyper::Method::POST,
        "/api/abac/evaluate",
        Some(serde_json::json!({
            "resource": "/test/data",
            "action": "GET",
            "app_id": app_fx.app_id.to_string(),
        })),
        Some(&fx.access_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["allowed"], false);
    assert_eq!(body["data"]["effect"], "deny");
    ta.cleanup().await;
}

#[tokio::test]
async fn evaluate_requires_auth() {
    let mut ta = build_app().await;

    let (status, _) = send_request(
        &mut ta.app,
        hyper::Method::POST,
        "/api/abac/evaluate",
        Some(serde_json::json!({
            "resource": "/api/test",
            "action": "GET",
        })),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    ta.cleanup().await;
}

#[tokio::test]
async fn evaluate_with_scoped_app_policy() {
    let mut ta = build_app().await;
    let fx = ta.register_default_user().await;
    ta.grant_api_access(fx.user_id).await;

    let app_fx = ta.create_test_app(&fx.access_token).await;

    let policy_name = unique_name("scoped");
    let (status, body) = send_request(
        &mut ta.app,
        hyper::Method::POST,
        "/api/policies",
        Some(serde_json::json!({
            "name": policy_name,
            "effect": "allow",
            "priority": 200,
            "app_id": app_fx.app_id.to_string(),
            "conditions": [],
        })),
        Some(&fx.access_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let policy_id: uuid::Uuid = body["data"]["id"].as_str().unwrap().parse().unwrap();
    ta.track_policy(policy_id);

    send_request(
        &mut ta.app,
        hyper::Method::POST,
        &format!("/api/users/{}/policies/{}", fx.user_id, policy_id),
        None,
        Some(&fx.access_token),
    )
    .await;

    let (status, body) = send_request(
        &mut ta.app,
        hyper::Method::POST,
        "/api/abac/evaluate",
        Some(serde_json::json!({
            "resource": "/api/test",
            "action": "GET",
            "app_id": app_fx.app_id.to_string(),
        })),
        Some(&fx.access_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["allowed"], true);
    ta.cleanup().await;
}
