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
#[ignore = "requires dedicated PERO_TEST_DATABASE_URL and PERO_TEST_REDIS_URL"]
async fn dashboard_creation_returns_json_for_success_and_validation_errors() {
    let fixture = database::DatabaseFixture::new().await;
    let config: AppConfig = serde_json::from_value(serde_json::json!({
        "database":{"url":fixture.url,"encrypt_key":"test-only-key","min_connections":1},
        "redis":{"url":std::env::var("PERO_TEST_REDIS_URL").unwrap()},
        "notification":{"endpoint":"https://notifications.example.test"},
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
    db.execute_unprepared("INSERT INTO admin_roles(user_id,role) SELECT id,'super_admin' FROM users; INSERT INTO user_mfa(user_id,secret_enc,enabled) SELECT id,pgp_sym_encrypt('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ',current_setting('app.encrypt_key')),true FROM users; UPDATE sso_sessions SET mfa_required=true,mfa_verified_at=now()").await.unwrap();
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
    // Client updates accept settings without a mutable Client ID.
    use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
    let created_app = user_center::db::entity::apps::Entity::find()
        .filter(user_center::db::entity::apps::Column::Code.eq("created-app"))
        .one(&db)
        .await
        .unwrap()
        .unwrap();
    let app_id = created_app.id.to_string();
    let client_fields = vec![
        ("csrf_token", csrf.as_str()),
        ("app_id", app_id.as_str()),
        ("identifier", "fixed-client"),
        ("client_type", "public"),
        ("secret", ""),
        ("name", "Client"),
        ("redirect_uris", "https://client.example.test/callback"),
        ("post_logout_redirect_uris", ""),
        ("scopes", "openid"),
        ("grant_types", "authorization_code"),
        ("require_pkce", "true"),
        ("access_token_ttl", "7200"),
        ("refresh_token_ttl", "86400"),
        ("id_token_ttl", "7200"),
    ];
    assert_eq!(
        post(&app, &cookies, "/dashboard/clients/new", &client_fields).await["code"],
        0
    );
    let client = user_center::db::entity::oauth_clients::Entity::find()
        .filter(user_center::db::entity::oauth_clients::Column::Identifier.eq("fixed-client"))
        .one(&db)
        .await
        .unwrap()
        .unwrap();
    let settings = client_fields
        .iter()
        .copied()
        .filter(|(key, _)| !["identifier", "app_id"].contains(key))
        .collect::<Vec<_>>();
    assert_eq!(
        post(
            &app,
            &cookies,
            &format!("/dashboard/clients/{}/edit", client.id),
            &settings
        )
        .await["code"],
        0
    );
    assert_eq!(
        user_center::db::entity::oauth_clients::Entity::find_by_id(client.id)
            .one(&db)
            .await
            .unwrap()
            .unwrap()
            .identifier,
        "fixed-client"
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
                ("email", "created_user@example.test"),
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
