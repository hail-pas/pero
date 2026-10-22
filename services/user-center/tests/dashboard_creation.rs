#[path = "support/database.rs"]
mod database;

use axum::{Router, body::Body, http::Request};
use axum_extra::extract::{CookieJar, cookie::Cookie};
use sea_orm::{ConnectionTrait, DbBackend, Statement};
use tower::ServiceExt;
use user_center::{config::AppConfig, state::app::AppState};

async fn post(
    app: &Router,
    cookies: &str,
    path: &str,
    fields: &[(&str, &str)],
) -> serde_json::Value {
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(fields.iter().copied())
        .finish();
    let response = app
        .clone()
        .oneshot(
            Request::post(path)
                .header("cookie", cookies)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(
        !response.status().is_redirection(),
        "{path} redirects an AJAX request"
    );
    assert_eq!(
        response.headers()["content-type"],
        "application/json",
        "{path}"
    );
    let body = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    serde_json::from_slice(&body).unwrap()
}

#[tokio::test]
#[ignore = "requires dedicated PERO_TEST_DATABASE_URL"]
async fn dashboard_creation_returns_json_for_success_and_validation_errors() {
    let fixture = database::DatabaseFixture::new().await;
    let config: AppConfig = serde_json::from_value(serde_json::json!({
        "database":{"url":fixture.url,"encrypt_key":"test-only-key","min_connections":1},
        "redis":{"url":"redis://127.0.0.1:1"},
        "sso":{"cookie_signing_secret":"test-only-signing-secret-long-enough"},
        "password_reset":{"signing_key":"test-only-reset-secret-long-enough"}
    }))
    .unwrap();
    let (db, guard) = user_center::db::init::init_db(&config).await.unwrap();
    fixture.migrate(&db).await;
    let cache = pero_cache_redis::RedisCacheStore::from_config(&config.redis).unwrap();
    let http =
        pero_http_client_reqwest::ReqwestHttpClient::from_config(&config.http_config).unwrap();
    let state = AppState::new(config, db.clone(), cache, http);
    let user_id = uuid::Uuid::now_v7();
    db.execute_raw(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "INSERT INTO users(id,username) VALUES($1,'dashboard_admin')",
        [user_id.into()],
    ))
    .await
    .unwrap();
    db.execute_unprepared("INSERT INTO identity_providers(code,name,kind,issuer) VALUES('local','Local','local','https://issuer.example.test'); INSERT INTO user_app_access(user_id,app_id) SELECT users.id,apps.id FROM users CROSS JOIN apps WHERE apps.code='user-center'").await.unwrap();
    let (token, _) = state
        .session_service()
        .create(user_id, None, None, None, None)
        .await
        .unwrap();
    let (jar, csrf) = state
        .web_security()
        .ensure_csrf(CookieJar::new().add(Cookie::new("pero_sso", token)));
    let cookies = jar
        .iter()
        .map(|cookie| format!("{}={}", cookie.name(), cookie.value()))
        .collect::<Vec<_>>()
        .join("; ");
    let app = user_center::router::build(state);

    let mut app_fields = vec![
        ("csrf_token", csrf.as_str()),
        ("code", "created-app"),
        ("name", "Created App"),
        ("app_type", "web"),
        ("description", ""),
        ("homepage_url", ""),
        ("logo_url", ""),
    ];
    assert_eq!(
        post(&app, &cookies, "/dashboard/apps/new", &app_fields).await["code"],
        0
    );
    assert_eq!(
        post(&app, &cookies, "/dashboard/apps/new", &app_fields).await["error"],
        "code_exists"
    );
    app_fields[1].1 = "another-app";
    app_fields[5].1 = "javascript:alert(1)";
    assert_eq!(
        post(&app, &cookies, "/dashboard/apps/new", &app_fields).await["error"],
        "invalid_url"
    );
    assert_eq!(
        post(
            &app,
            &cookies,
            "/dashboard/users/new",
            &[
                ("csrf_token", &csrf),
                ("username", "created_user"),
                ("password", "OriginalPass123!"),
                ("email", ""),
                ("phone", ""),
                ("nickname", ""),
                ("avatar_url", "")
            ]
        )
        .await["code"],
        0
    );
    assert_eq!(
        post(
            &app,
            &cookies,
            "/dashboard/providers/new",
            &[
                ("csrf_token", &csrf),
                ("code", "created-provider"),
                ("name", "Created Provider"),
                ("kind", "oauth2"),
                ("icon", ""),
                ("issuer", ""),
                ("authorization_endpoint", ""),
                ("token_endpoint", ""),
                ("userinfo_endpoint", ""),
                ("jwks_uri", ""),
                ("end_session_endpoint", ""),
                ("client_id", ""),
                ("client_secret", ""),
                ("scopes", ""),
                ("settings", "")
            ]
        )
        .await["code"],
        0
    );
    assert_eq!(
        app.oneshot(
            Request::get("/sso/verification?status=success")
                .body(Body::empty())
                .unwrap()
        )
        .await
        .unwrap()
        .status(),
        404
    );

    guard.shutdown().await;
    fixture.cleanup().await;
}
