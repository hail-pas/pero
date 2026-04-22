mod common;

use common::*;
use hyper::StatusCode;

async fn create_app_with_client(ta: &mut TestApp, token: &str) -> (AppFixture, ClientFixture) {
    let app_fx = ta.create_test_app(token).await;
    let client_fx = ta
        .create_test_client(app_fx.app_id, &app_fx.code, token)
        .await;
    (app_fx, client_fx)
}

#[tokio::test]
async fn create_and_list_clients() {
    let mut ta = build_app().await;
    let fx = ta.register_default_user().await;
    ta.grant_api_access(fx.user_id).await;
    let _ = create_app_with_client(&mut ta, &fx.access_token).await;

    let (status, body) = send_request(
        &mut ta.app,
        hyper::Method::GET,
        "/api/oauth2/clients?page=1&page_size=10",
        None,
        Some(&fx.access_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["data"]["total"].as_i64().unwrap() >= 1);
    ta.cleanup().await;
}

#[tokio::test]
async fn get_update_delete_client() {
    let mut ta = build_app().await;
    let fx = ta.register_default_user().await;
    ta.grant_api_access(fx.user_id).await;
    let (_, client_fx) = create_app_with_client(&mut ta, &fx.access_token).await;

    let (status, body) = send_request(
        &mut ta.app,
        hyper::Method::GET,
        &format!("/api/oauth2/clients/{}", client_fx.client_id),
        None,
        Some(&fx.access_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["id"], client_fx.client_id.to_string());

    let (status, body) = send_request(
        &mut ta.app,
        hyper::Method::PUT,
        &format!("/api/oauth2/clients/{}", client_fx.client_id),
        Some(serde_json::json!({
            "client_name": "updated_client_name",
        })),
        Some(&fx.access_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["client_name"], "updated_client_name");

    let (status, _) = send_request(
        &mut ta.app,
        hyper::Method::DELETE,
        &format!("/api/oauth2/clients/{}", client_fx.client_id),
        None,
        Some(&fx.access_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    ta.cleanup().await;
}

#[tokio::test]
async fn token_revoke_flow() {
    let mut ta = build_app().await;
    let fx = ta.register_default_user().await;
    ta.grant_api_access(fx.user_id).await;

    let (_, client_fx) = create_app_with_client(&mut ta, &fx.access_token).await;

    let code = uuid::Uuid::new_v4().to_string().replace('-', "");
    let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    sqlx::query(
        "INSERT INTO oauth2_authorization_codes (code, client_id, user_id, redirect_uri, scopes, code_challenge, code_challenge_method, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7, now() + interval '10 minutes')",
    )
    .bind(&code)
    .bind(client_fx.client_id)
    .bind(fx.user_id)
    .bind("http://localhost:3000/callback")
    .bind(&vec!["openid".to_string(), "profile".to_string()])
    .bind(challenge)
    .bind("S256")
    .execute(&ta.db)
    .await
    .unwrap();

    let (status, body) = send_form_request(
        &mut ta.app,
        hyper::Method::POST,
        "/oauth2/token",
        &[
            ("grant_type", "authorization_code".to_string()),
            ("code", code),
            ("redirect_uri", "http://localhost:3000/callback".to_string()),
            ("client_id", client_fx.client_id_str.clone()),
            ("client_secret", client_fx.client_secret.clone()),
            (
                "code_verifier",
                "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk".to_string(),
            ),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK, "token exchange failed: {body:?}");
    let refresh_token = body["refresh_token"].as_str().unwrap().to_string();

    let (status, _) = send_form_request(
        &mut ta.app,
        hyper::Method::POST,
        "/oauth2/revoke",
        &[
            ("token", refresh_token),
            ("client_id", client_fx.client_id_str.clone()),
            ("client_secret", client_fx.client_secret.clone()),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    ta.cleanup().await;
}

#[tokio::test]
async fn token_exchange_rejects_disallowed_authorization_code_grant() {
    let mut ta = build_app().await;
    let fx = ta.register_default_user().await;
    ta.grant_api_access(fx.user_id).await;
    let app_fx = ta.create_test_app(&fx.access_token).await;

    let (status, body) = send_request(
        &mut ta.app,
        hyper::Method::POST,
        "/api/oauth2/clients",
        Some(serde_json::json!({
            "app_id": app_fx.app_id.to_string(),
            "client_name": "refresh_only_client",
            "redirect_uris": ["http://localhost:3000/callback"],
            "grant_types": ["refresh_token"],
            "scopes": ["openid", "profile"],
        })),
        Some(&fx.access_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "create client failed: {body:?}");
    let client_id: uuid::Uuid = body["data"]["client"]["id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    ta.track_client(client_id);
    let client_id_str = body["data"]["client"]["client_id"].as_str().unwrap();
    let client_secret = body["data"]["client_secret"].as_str().unwrap();

    let code = uuid::Uuid::new_v4().to_string().replace('-', "");
    sqlx::query(
        "INSERT INTO oauth2_authorization_codes (code, client_id, user_id, redirect_uri, scopes, code_challenge, code_challenge_method, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7, now() + interval '10 minutes')",
    )
    .bind(&code)
    .bind(client_id)
    .bind(fx.user_id)
    .bind("http://localhost:3000/callback")
    .bind(&vec!["openid".to_string()])
    .bind("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
    .bind("S256")
    .execute(&ta.db)
    .await
    .unwrap();

    let (status, _body) = send_form_request(
        &mut ta.app,
        hyper::Method::POST,
        "/oauth2/token",
        &[
            ("grant_type", "authorization_code".to_string()),
            ("code", code),
            ("redirect_uri", "http://localhost:3000/callback".to_string()),
            ("client_id", client_id_str.to_string()),
            ("client_secret", client_secret.to_string()),
            (
                "code_verifier",
                "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk".to_string(),
            ),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    ta.cleanup().await;
}

#[tokio::test]
async fn token_exchange_rejects_disallowed_refresh_token_grant() {
    let mut ta = build_app().await;
    let fx = ta.register_default_user().await;
    ta.grant_api_access(fx.user_id).await;
    let app_fx = ta.create_test_app(&fx.access_token).await;

    let (status, body) = send_request(
        &mut ta.app,
        hyper::Method::POST,
        "/api/oauth2/clients",
        Some(serde_json::json!({
            "app_id": app_fx.app_id.to_string(),
            "client_name": "auth_code_only_client",
            "redirect_uris": ["http://localhost:3000/callback"],
            "grant_types": ["authorization_code"],
            "scopes": ["openid", "profile"],
        })),
        Some(&fx.access_token),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "create client failed: {body:?}");
    let client_id: uuid::Uuid = body["data"]["client"]["id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    ta.track_client(client_id);
    let client_id_str = body["data"]["client"]["client_id"].as_str().unwrap();
    let client_secret = body["data"]["client_secret"].as_str().unwrap();

    let refresh_token = uuid::Uuid::new_v4().to_string().replace('-', "");
    sqlx::query(
        "INSERT INTO oauth2_tokens (client_id, user_id, refresh_token, scopes, auth_time, expires_at) VALUES ($1, $2, $3, $4, $5, now() + interval '1 day')",
    )
    .bind(client_id)
    .bind(fx.user_id)
    .bind(pero::shared::utils::sha256_hex(&refresh_token))
    .bind(&vec!["openid".to_string()])
    .bind(chrono::Utc::now().timestamp())
    .execute(&ta.db)
    .await
    .unwrap();

    let (status, _body) = send_form_request(
        &mut ta.app,
        hyper::Method::POST,
        "/oauth2/token",
        &[
            ("grant_type", "refresh_token".to_string()),
            ("refresh_token", refresh_token),
            ("client_id", client_id_str.to_string()),
            ("client_secret", client_secret.to_string()),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    ta.cleanup().await;
}
