#[path = "support/database.rs"]
mod database;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use sea_orm::ConnectionTrait;
use tower::ServiceExt;
use user_center::{config::AppConfig, service::security as sec, state::app::AppState};
use uuid::Uuid;

async fn get(app: &Router, token: &str, path: &str) -> (StatusCode, serde_json::Value) {
    let response = app
        .clone()
        .oneshot(
            Request::get(path)
                .header("accept", "application/json")
                .header("cookie", format!("pero_sso={token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    let value = serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
    (status, value)
}

#[tokio::test]
#[ignore = "requires dedicated PERO_TEST_DATABASE_URL and PERO_TEST_REDIS_URL"]
async fn navigation_and_dashboard_share_live_administrator_entitlement() {
    let fixture = database::DatabaseFixture::new().await;
    let config: AppConfig = serde_json::from_value(serde_json::json!({
        "database": {"url": fixture.url, "encrypt_key": "navigation-test-key", "min_connections": 1},
        "redis": {"url": std::env::var("PERO_TEST_REDIS_URL").unwrap()},
        "sso": {"cookie_signing_secret": "navigation-test-signing-secret-long-enough"}
    })).unwrap();
    let (db, guard) = user_center::db::init::init_db(&config).await.unwrap();
    fixture.migrate(&db).await;
    let cache = pero_cache_redis::RedisCacheStore::from_config(&config.redis).unwrap();
    let http =
        pero_http_client_reqwest::ReqwestHttpClient::from_config(&config.http_config).unwrap();
    let state = AppState::new(config, db.clone(), cache, http);
    let app = user_center::router::build(state.clone());
    let (status, value) = get(&app, "", "/").await;
    assert_eq!(status, StatusCode::OK);
    assert!(value["data"]["layout"].is_null());

    let mut admin_token = String::new();
    for (username, role, allowed) in [
        ("super", Some("super_admin"), true),
        ("admin", Some("admin"), true),
        ("member", None, false),
    ] {
        let user = Uuid::now_v7();
        sec::execute(
            &db,
            "INSERT INTO users(id,username) VALUES($1,$2)",
            vec![user.into(), username.into()],
        )
        .await
        .unwrap();
        if let Some(role) = role {
            sec::execute(
                &db,
                "INSERT INTO admin_roles(user_id,role) VALUES($1,$2)",
                vec![user.into(), role.into()],
            )
            .await
            .unwrap();
        }
        if role == Some("admin") {
            sec::execute(
                &db,
                "INSERT INTO admin_permission_state(user_id) VALUES($1)",
                vec![user.into()],
            )
            .await
            .unwrap();
        }
        let (token, session) = state
            .session_service()
            .create(user, None, None, None, None)
            .await
            .unwrap();
        sec::execute(&db, "INSERT INTO user_mfa(user_id,secret_enc,enabled) VALUES($1,pgp_sym_encrypt('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ',current_setting('app.encrypt_key')),true)", vec![user.into()]).await.unwrap();
        sec::execute(
            &db,
            "UPDATE sso_sessions SET mfa_verified_at=now() WHERE id=$1",
            vec![session.into()],
        )
        .await
        .unwrap();
        for path in ["/", "/account/profile", "/account/security"] {
            let (status, value) = get(&app, &token, path).await;
            assert_eq!(status, StatusCode::OK, "{username} {path}: {value}");
            assert_eq!(
                value["data"]["layout"]["can_access_dashboard"], allowed,
                "{username} {path}"
            );
        }
        let (status, value) = get(&app, &token, "/dashboard/apps").await;
        assert_eq!(
            status,
            if allowed {
                StatusCode::OK
            } else {
                StatusCode::FORBIDDEN
            }
        );
        if allowed {
            assert_eq!(value["data"]["layout"]["can_access_dashboard"], true);
            // MFA remains mandatory for both administrator roles.
            sec::execute(
                &db,
                "UPDATE user_mfa SET enabled=false WHERE user_id=$1",
                vec![user.into()],
            )
            .await
            .unwrap();
            let (_, challenge) = get(&app, &token, "/dashboard/apps").await;
            assert_eq!(
                challenge["redirect"],
                "/account/security?redirect=%2Fdashboard%2Fapps"
            );
            sec::execute(
                &db,
                "UPDATE user_mfa SET enabled=true WHERE user_id=$1",
                vec![user.into()],
            )
            .await
            .unwrap();
        }
        if username == "admin" {
            admin_token = token;
        }
    }

    // An already-open browser session must use the current role, not a token snapshot.
    db.execute_unprepared(
        "DELETE FROM admin_roles WHERE user_id=(SELECT id FROM users WHERE username='admin')",
    )
    .await
    .unwrap();
    for path in ["/", "/account/profile"] {
        let (status, value) = get(&app, &admin_token, path).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(value["data"]["layout"]["can_access_dashboard"], false);
    }
    assert_eq!(
        get(&app, &admin_token, "/dashboard/apps").await.0,
        StatusCode::FORBIDDEN
    );

    // Failed permission lookup is an unavailable service, never an ordinary-user result.
    db.execute_unprepared("ALTER TABLE admin_roles RENAME TO unavailable_admin_roles")
        .await
        .unwrap();
    for path in ["/", "/account/profile", "/dashboard/apps"] {
        assert_eq!(
            get(&app, &admin_token, path).await.0,
            StatusCode::SERVICE_UNAVAILABLE,
            "{path}"
        );
    }
    guard.shutdown().await;
    fixture.cleanup().await;
}
