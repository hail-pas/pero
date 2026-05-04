#[path = "../common/mod.rs"]
mod common;

use axum::http::{Method, StatusCode};
use common::{RealTestApp, form_request_with_headers, json_request, text_request_with_headers};
use pero::domain::app::models::CreateAppRequest;
use pero::domain::oauth::models::CreateClientRequest;
use pero::domain::oauth::repo::CreateAuthCodeParams;
use pero::domain::sso::models::{AuthorizeParams, SsoSession};
use pero::shared::constants::cookies::SSO_SESSION;
use pero::shared::constants::oauth2::{GRANT_TYPE_AUTH_CODE, GRANT_TYPE_REFRESH_TOKEN, scopes};
use serde_json::json;
use sha2::Digest;

fn unique_prefix(name: &str) -> String {
    format!("real_{name}_{}_", uuid::Uuid::new_v4().simple())
}

fn pkce_challenge(verifier: &str) -> String {
    base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        sha2::Digest::finalize(sha2::Sha256::new_with_prefix(verifier.as_bytes())),
    )
}

fn extract_csrf_token(html: &str) -> String {
    let marker = "name=\"csrf_token\" value=\"";
    let start = html.find(marker).expect("csrf input should exist") + marker.len();
    let rest = &html[start..];
    let end = rest.find('"').expect("csrf value should close");
    rest[..end].to_string()
}

#[tokio::test]
async fn real_backend_register_login_refresh_and_cleanup() {
    let prefix = unique_prefix("auth");
    let app = RealTestApp::new(&prefix).await;
    let username = format!("{prefix}user");
    let email = format!("{prefix}user@example.test");

    let (register_status, register_body) = json_request(
        app.app.clone(),
        Method::POST,
        "/api/identity/register",
        Some(json!({
            "username": username,
            "email": email,
            "password": "password123"
        })),
        None,
    )
    .await;
    assert_eq!(register_status, StatusCode::OK, "{register_body:?}");

    let (duplicate_status, duplicate_body) = json_request(
        app.app.clone(),
        Method::POST,
        "/api/identity/register",
        Some(json!({
            "username": username,
            "email": email,
            "password": "password123"
        })),
        None,
    )
    .await;
    assert_eq!(duplicate_status, StatusCode::CONFLICT, "{duplicate_body:?}");

    let (bad_login_status, bad_login_body) = json_request(
        app.app.clone(),
        Method::POST,
        "/api/identity/login",
        Some(json!({
            "identifier": username,
            "password": "wrongpassword"
        })),
        None,
    )
    .await;
    assert_eq!(
        bad_login_status,
        StatusCode::UNAUTHORIZED,
        "{bad_login_body:?}"
    );

    let access = register_body["data"]["access_token"]
        .as_str()
        .unwrap()
        .to_string();
    let refresh = register_body["data"]["refresh_token"]
        .as_str()
        .unwrap()
        .to_string();

    let user = app
        .state
        .repos
        .users
        .find_by_username(&username)
        .await
        .unwrap()
        .unwrap();
    let (update_me_status, update_me_body) = json_request(
        app.app.clone(),
        Method::PUT,
        "/api/users/me",
        Some(json!({
            "email": format!("{prefix}user.new@example.test"),
            "nickname": "Real Identity API",
            "avatar_url": "https://cdn.example.test/avatar.png"
        })),
        Some(&access),
    )
    .await;
    assert_eq!(update_me_status, StatusCode::OK, "{update_me_body:?}");
    assert_eq!(update_me_body["data"]["nickname"], "Real Identity API");

    let (list_users_status, list_users_body) = json_request(
        app.app.clone(),
        Method::GET,
        "/api/users?page=1&page_size=50",
        None,
        Some(&access),
    )
    .await;
    assert_eq!(list_users_status, StatusCode::OK, "{list_users_body:?}");
    assert!(list_users_body["data"]["total"].as_i64().unwrap() >= 1);

    let (get_user_status, get_user_body) = json_request(
        app.app.clone(),
        Method::GET,
        &format!("/api/users/{}", user.id),
        None,
        Some(&access),
    )
    .await;
    assert_eq!(get_user_status, StatusCode::OK, "{get_user_body:?}");

    let (update_user_status, update_user_body) = json_request(
        app.app.clone(),
        Method::PUT,
        &format!("/api/users/{}", user.id),
        Some(json!({
            "nickname": "Real Admin Updated",
            "status": 1
        })),
        Some(&access),
    )
    .await;
    assert_eq!(update_user_status, StatusCode::OK, "{update_user_body:?}");
    assert_eq!(update_user_body["data"]["nickname"], "Real Admin Updated");

    let (set_attrs_status, set_attrs_body) = json_request(
        app.app.clone(),
        Method::PUT,
        &format!("/api/users/{}/attributes", user.id),
        Some(json!({
            "attributes": [
                { "key": "department", "value": "engineering" },
                { "key": "tier", "value": "gold" }
            ]
        })),
        Some(&access),
    )
    .await;
    assert_eq!(set_attrs_status, StatusCode::OK, "{set_attrs_body:?}");

    let (list_attrs_status, list_attrs_body) = json_request(
        app.app.clone(),
        Method::GET,
        &format!("/api/users/{}/attributes", user.id),
        None,
        Some(&access),
    )
    .await;
    assert_eq!(list_attrs_status, StatusCode::OK, "{list_attrs_body:?}");
    assert_eq!(list_attrs_body["data"].as_array().unwrap().len(), 2);

    let (delete_attr_status, delete_attr_body) = json_request(
        app.app.clone(),
        Method::DELETE,
        &format!("/api/users/{}/attributes/tier", user.id),
        None,
        Some(&access),
    )
    .await;
    assert_eq!(delete_attr_status, StatusCode::OK, "{delete_attr_body:?}");

    let (refresh_status, refresh_body) = json_request(
        app.app.clone(),
        Method::POST,
        "/auth/refresh",
        Some(json!({ "refresh_token": refresh })),
        None,
    )
    .await;
    assert_eq!(refresh_status, StatusCode::OK, "{refresh_body:?}");

    let (password_status, password_body) = json_request(
        app.app.clone(),
        Method::PUT,
        "/api/identity/password/change",
        Some(json!({
            "old_password": "password123",
            "new_password": "newpassword123"
        })),
        Some(&access),
    )
    .await;
    assert_eq!(password_status, StatusCode::OK, "{password_body:?}");

    app.cleanup().await;
    let remaining: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE username LIKE $1")
        .bind(format!("{prefix}%"))
        .fetch_one(&app.db)
        .await
        .unwrap();
    assert_eq!(remaining, 0);
}

#[tokio::test]
async fn real_backend_oauth_token_and_revoke_use_real_persistence() {
    let prefix = unique_prefix("oauth");
    let app = RealTestApp::new(&prefix).await;
    let oauth_app = app
        .state
        .repos
        .apps
        .create(&CreateAppRequest {
            name: format!("{prefix}Token App"),
            code: format!("{prefix}token_app"),
            description: None,
        })
        .await
        .unwrap();
    let client_secret = "client-secret";
    let client = app
        .state
        .repos
        .oauth2_clients
        .create(
            &format!("{prefix}client"),
            &pero::shared::crypto::hash_secret(client_secret).unwrap(),
            &CreateClientRequest {
                app_id: oauth_app.id,
                client_name: format!("{prefix}Token Client"),
                redirect_uris: vec![format!("https://{prefix}app.example.test/callback")],
                grant_types: vec![GRANT_TYPE_AUTH_CODE.into(), GRANT_TYPE_REFRESH_TOKEN.into()],
                scopes: vec![scopes::OPENID.into(), scopes::EMAIL.into()],
                post_logout_redirect_uris: vec![],
            },
        )
        .await
        .unwrap();
    let user = app
        .state
        .repos
        .users
        .create_with_password(
            &format!("{prefix}user"),
            Some(&format!("{prefix}user@example.test")),
            None,
            None,
            &pero::shared::crypto::hash_secret("password123").unwrap(),
        )
        .await
        .unwrap();
    let verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~123456";
    let code = format!("{prefix}auth_code");
    let redirect_uri = format!("https://{prefix}app.example.test/callback");
    app.state
        .repos
        .auth_codes
        .create_auth_code(CreateAuthCodeParams {
            code: code.clone(),
            client_id: client.id,
            user_id: user.id,
            redirect_uri: redirect_uri.clone(),
            scopes: vec![scopes::OPENID.into(), scopes::EMAIL.into()],
            code_challenge: pkce_challenge(verifier),
            code_challenge_method: "S256".into(),
            nonce: Some(format!("{prefix}nonce")),
            sid: Some(format!("{prefix}sid")),
            auth_time: 123,
            ttl_minutes: 5,
        })
        .await
        .unwrap();

    let (token_status, token_body) = form_request_with_headers(
        app.app.clone(),
        Method::POST,
        "/oauth2/token",
        &[
            ("grant_type", "authorization_code".into()),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("client_id", client.client_id.clone()),
            ("client_secret", client_secret.into()),
            ("code_verifier", verifier.into()),
        ],
        &[],
    )
    .await;
    assert_eq!(token_status, StatusCode::OK, "{token_body:?}");
    assert!(token_body["access_token"].is_string());
    let refresh = token_body["refresh_token"].as_str().unwrap().to_string();

    let (refresh_status, refresh_body) = form_request_with_headers(
        app.app.clone(),
        Method::POST,
        "/oauth2/token",
        &[
            ("grant_type", "refresh_token".into()),
            ("client_id", client.client_id.clone()),
            ("client_secret", client_secret.into()),
            ("refresh_token", refresh),
        ],
        &[],
    )
    .await;
    assert_eq!(refresh_status, StatusCode::OK, "{refresh_body:?}");
    let rotated_refresh = refresh_body["refresh_token"].as_str().unwrap().to_string();

    let (revoke_status, revoke_body) = form_request_with_headers(
        app.app.clone(),
        Method::POST,
        "/oauth2/revoke",
        &[
            ("token", rotated_refresh.clone()),
            ("client_id", client.client_id),
            ("client_secret", client_secret.into()),
        ],
        &[],
    )
    .await;
    assert_eq!(revoke_status, StatusCode::OK, "{revoke_body:?}");
    assert!(
        app.state
            .repos
            .refresh_tokens
            .find_revoked_by_token(&rotated_refresh)
            .await
            .unwrap()
            .is_some()
    );

    app.cleanup().await;
}

#[tokio::test]
async fn real_backend_sso_consent_uses_real_redis_and_auth_code_store() {
    let prefix = unique_prefix("sso");
    let app = RealTestApp::new(&prefix).await;
    let oauth_app = app
        .state
        .repos
        .apps
        .create(&CreateAppRequest {
            name: format!("{prefix}Consent App"),
            code: format!("{prefix}consent_app"),
            description: None,
        })
        .await
        .unwrap();
    let client = app
        .state
        .repos
        .oauth2_clients
        .create(
            &format!("{prefix}client"),
            &pero::shared::crypto::hash_secret("secret").unwrap(),
            &CreateClientRequest {
                app_id: oauth_app.id,
                client_name: format!("{prefix}Consent Client"),
                redirect_uris: vec![format!("https://{prefix}app.example.test/callback")],
                grant_types: vec![GRANT_TYPE_AUTH_CODE.into(), GRANT_TYPE_REFRESH_TOKEN.into()],
                scopes: vec![scopes::OPENID.into(), scopes::EMAIL.into()],
                post_logout_redirect_uris: vec![],
            },
        )
        .await
        .unwrap();
    let user = app
        .state
        .repos
        .users
        .create_with_password(
            &format!("{prefix}user"),
            Some(&format!("{prefix}user@example.test")),
            None,
            Some("Consent"),
            &pero::shared::crypto::hash_secret("password123").unwrap(),
        )
        .await
        .unwrap();
    let sso = SsoSession {
        authorize_params: AuthorizeParams {
            client_id: client.client_id,
            redirect_uri: format!("https://{prefix}app.example.test/callback"),
            response_type: "code".into(),
            scope: Some("openid email".into()),
            state: Some(format!("{prefix}state")),
            code_challenge: "a".repeat(43),
            code_challenge_method: "S256".into(),
            nonce: Some(format!("{prefix}nonce")),
        },
        user_id: Some(user.id),
        authenticated: true,
        auth_time: Some(123),
    };
    let sid = app.state.repos.sso_sessions.create(&sso, 60).await.unwrap();
    let cookie = format!("{SSO_SESSION}={sid}");

    let (get_status, html) = text_request_with_headers(
        app.app.clone(),
        Method::GET,
        "/sso/consent",
        &[("cookie", cookie.clone())],
    )
    .await;
    assert_eq!(get_status, StatusCode::OK, "{html}");
    let csrf = extract_csrf_token(&html);

    let (post_status, post_body) = form_request_with_headers(
        app.app.clone(),
        Method::POST,
        "/sso/consent",
        &[("action", "allow".into()), ("csrf_token", csrf)],
        &[("cookie", cookie)],
    )
    .await;
    assert!(post_status.is_redirection(), "{post_body:?}");
    assert!(
        app.state
            .repos
            .sso_sessions
            .get(&sid)
            .await
            .unwrap()
            .is_none()
    );
    let issued_codes: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM oauth2_authorization_codes WHERE user_id = $1 AND used = false",
    )
    .bind(user.id)
    .fetch_one(&app.db)
    .await
    .unwrap();
    assert_eq!(issued_codes, 1);

    app.cleanup().await;
}
