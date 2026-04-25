#[path = "../common/mod.rs"]
mod common;

use common::*;
use hyper::StatusCode;
use tower::ServiceExt;

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
async fn abac_allows_when_any_role_matches() {
    let mut ta = build_app().await;
    let fx = ta.register_default_user().await;

    let policy_id = uuid::Uuid::new_v4();
    let policy_name = unique_name("role_viewer");
    sqlx::query(
        "INSERT INTO policies (id, name, effect, priority, enabled) VALUES ($1, $2, 'allow', 100, true)",
    )
    .bind(policy_id)
    .bind(&policy_name)
    .execute(&ta.db)
    .await
    .unwrap();
    ta.track_policy(policy_id);

    for (ct, key, op, val) in [
        ("subject", "role", "eq", "viewer"),
        ("resource", "path", "wildcard", "/api/**"),
        ("action", "method", "in", "GET,POST,PUT,DELETE"),
    ] {
        sqlx::query(
            "INSERT INTO policy_conditions (policy_id, condition_type, key, operator, value) VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(policy_id)
        .bind(ct)
        .bind(key)
        .bind(op)
        .bind(val)
        .execute(&ta.db)
        .await
        .unwrap();
    }

    sqlx::query("INSERT INTO user_policies (user_id, policy_id) VALUES ($1, $2)")
        .bind(fx.user_id)
        .bind(policy_id)
        .execute(&ta.db)
        .await
        .unwrap();

    let request: hyper::Request<axum::body::Body> = hyper::Request::builder()
        .method(hyper::Method::GET)
        .uri("/api/policies?page=1&page_size=10")
        .header(
            hyper::header::AUTHORIZATION,
            format!("Bearer {}", fx.access_token),
        )
        .body(axum::body::Body::empty())
        .unwrap();
    let response = ta.app.clone().oneshot(request).await.unwrap();
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "should be denied: JWT role is 'user', policy requires 'viewer'"
    );

    sqlx::query(
        "INSERT INTO user_attributes (user_id, key, value) VALUES ($1, 'role', 'viewer') ON CONFLICT (user_id, key) DO UPDATE SET value = 'viewer'",
    )
    .bind(fx.user_id)
    .execute(&ta.db)
    .await
    .unwrap();

    ta.clear_user_cache(fx.user_id).await;

    let request: hyper::Request<axum::body::Body> = hyper::Request::builder()
        .method(hyper::Method::GET)
        .uri("/api/policies?page=1&page_size=10")
        .header(
            hyper::header::AUTHORIZATION,
            format!("Bearer {}", fx.access_token),
        )
        .body(axum::body::Body::empty())
        .unwrap();
    let response = ta.app.clone().oneshot(request).await.unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "should be allowed: user_attrs has 'viewer' (multi-valued with JWT 'user')"
    );

    ta.cleanup().await;
}

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
            "name": unique_name("updated_policy"),
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
    assert!(
        items
            .iter()
            .any(|p| p["id"] == policy_fx.policy_id.to_string())
    );

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

    let (status, resp) = send_basic_auth_request(
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
    ta.track_policy(resp["data"]["id"].as_str().unwrap().parse().unwrap());

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

#[tokio::test]
async fn app_scoped_policy_cannot_match_admin_route() {
    let mut ta = build_app().await;
    let fx = ta.register_default_user().await;

    let app_fx = ta.create_test_app_direct().await;

    let policy_id = uuid::Uuid::new_v4();
    let policy_name = unique_name("app_leak_test");
    sqlx::query(
        "INSERT INTO policies (id, name, effect, priority, enabled, app_id) VALUES ($1, $2, 'allow', 100, true, $3)",
    )
    .bind(policy_id)
    .bind(&policy_name)
    .bind(app_fx.app_id)
    .execute(&ta.db)
    .await
    .unwrap();
    ta.track_policy(policy_id);

    for (ct, key, op, val) in [
        ("resource", "path", "wildcard", "/api/**"),
        ("action", "method", "in", "GET,POST,PUT,DELETE"),
    ] {
        sqlx::query(
            "INSERT INTO policy_conditions (policy_id, condition_type, key, operator, value) VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(policy_id)
        .bind(ct)
        .bind(key)
        .bind(op)
        .bind(val)
        .execute(&ta.db)
        .await
        .unwrap();
    }

    sqlx::query("INSERT INTO user_policies (user_id, policy_id) VALUES ($1, $2)")
        .bind(fx.user_id)
        .bind(policy_id)
        .execute(&ta.db)
        .await
        .unwrap();

    ta.clear_user_cache(fx.user_id).await;

    let request: hyper::Request<axum::body::Body> = hyper::Request::builder()
        .method(hyper::Method::GET)
        .uri("/api/policies?page=1&page_size=10")
        .header(
            hyper::header::AUTHORIZATION,
            format!("Bearer {}", fx.access_token),
        )
        .header("x-app-id", app_fx.app_id.to_string())
        .body(axum::body::Body::empty())
        .unwrap();
    let response = ta.app.clone().oneshot(request).await.unwrap();

    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "app-scoped policy should NOT match Pero admin route"
    );

    ta.cleanup().await;
}

#[tokio::test]
async fn global_policy_matches_admin_route_without_app_id() {
    let mut ta = build_app().await;
    let fx = ta.register_default_user().await;

    let policy_id = uuid::Uuid::new_v4();
    let policy_name = unique_name("global_admin_test");
    sqlx::query(
        "INSERT INTO policies (id, name, effect, priority, enabled) VALUES ($1, $2, 'allow', 100, true)",
    )
    .bind(policy_id)
    .bind(&policy_name)
    .execute(&ta.db)
    .await
    .unwrap();
    ta.track_policy(policy_id);

    for (ct, key, op, val) in [
        ("resource", "path", "wildcard", "/api/**"),
        ("action", "method", "in", "GET,POST,PUT,DELETE"),
    ] {
        sqlx::query(
            "INSERT INTO policy_conditions (policy_id, condition_type, key, operator, value) VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(policy_id)
        .bind(ct)
        .bind(key)
        .bind(op)
        .bind(val)
        .execute(&ta.db)
        .await
        .unwrap();
    }

    sqlx::query("INSERT INTO user_policies (user_id, policy_id) VALUES ($1, $2)")
        .bind(fx.user_id)
        .bind(policy_id)
        .execute(&ta.db)
        .await
        .unwrap();

    ta.clear_user_cache(fx.user_id).await;

    let request: hyper::Request<axum::body::Body> = hyper::Request::builder()
        .method(hyper::Method::GET)
        .uri("/api/policies?page=1&page_size=10")
        .header(
            hyper::header::AUTHORIZATION,
            format!("Bearer {}", fx.access_token),
        )
        .body(axum::body::Body::empty())
        .unwrap();
    let response = ta.app.clone().oneshot(request).await.unwrap();

    assert_eq!(
        response.status(),
        StatusCode::OK,
        "global policy should match Pero admin route"
    );

    ta.cleanup().await;
}
