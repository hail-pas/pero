#[path = "support/database.rs"]
mod database;
use axum::{
    Form,
    extract::{Path, State},
    http::Request,
};
use axum_extra::extract::cookie::CookieJar;
use sea_orm::{ConnectionTrait, DbBackend, Statement};
use tower::ServiceExt;
use uuid::Uuid;
const PRIVATE: &str = include_str!("../../../tests/fixtures/rsa-private.pem");
const PUBLIC: &str = include_str!("../../../tests/fixtures/rsa-public.pem");
async fn sql(db: &sea_orm::DatabaseConnection, q: &str, v: Vec<sea_orm::Value>) {
    db.execute_raw(Statement::from_sql_and_values(DbBackend::Postgres, q, v))
        .await
        .unwrap();
}
fn jwt(
    issuer: &str,
    sub: Uuid,
    aud: &str,
    sid: Uuid,
    scope: Option<&str>,
    at_hash: Option<String>,
) -> String {
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let mut c = serde_json::json!({"iss":issuer,"sub":sub.to_string(),"aud":aud,"sid":sid.to_string(),"exp":now+3600,"iat":now});
    if let Some(s) = scope {
        c["scope"] = s.into();
    }
    if let Some(s) = at_hash {
        c["at_hash"] = s.into();
    }
    let mut h = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    h.kid = Some("review".into());
    jsonwebtoken::encode(
        &h,
        &c,
        &jsonwebtoken::EncodingKey::from_rsa_pem(PRIVATE.as_bytes()).unwrap(),
    )
    .unwrap()
}
#[tokio::test]
#[ignore = "requires dedicated PERO_TEST_DATABASE_URL"]
async fn authorization_and_recovery_regressions() {
    let fixture = database::DatabaseFixture::new().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let issuer = format!("http://{}", listener.local_addr().unwrap());
    let cfg:user_center::config::AppConfig=serde_json::from_value(serde_json::json!({
 "database":{"url":fixture.url,"encrypt_key":"test-only-key","min_connections":1,"max_connections":8},
 "redis":{"url":"redis://127.0.0.1:1","connect_timeout_secs":1,"command_timeout_secs":1},
 "sso":{"cookie_signing_secret":"review-test-only-secret-long-enough","session_idle_ttl_seconds":1800},
 "oidc":{"issuer":issuer},"password_reset":{"signing_key":"review-test-only-reset-secret-long-enough"}})).unwrap();
    let (db, guard) = user_center::db::init::init_db(&cfg).await.unwrap();
    fixture.migrate(&db).await;
    let cache = pero_cache_redis::RedisCacheStore::from_config(&cfg.redis).unwrap();
    let http = pero_http_client_reqwest::ReqwestHttpClient::from_config(&cfg.http_config).unwrap();
    let state = user_center::state::app::AppState::new(cfg, db.clone(), cache, http);
    let (user, provider, key) = (Uuid::now_v7(), Uuid::now_v7(), Uuid::now_v7());
    sql(&db,"INSERT INTO users(id,username,email,email_verified_at) VALUES ($1,'review_user','old@example.test',now())",vec![user.into()]).await;
    sql(&db,"INSERT INTO identity_providers(id,code,name,kind,issuer) VALUES ($1,'local','Local','local',$2)",vec![provider.into(),issuer.clone().into()]).await;
    sql(&db,"INSERT INTO identity_provider_keys(id,provider_id,kid,public_key_pem,active) VALUES ($1,$2,'review',$3,true)",vec![key.into(),provider.into(),PUBLIC.into()]).await;
    user_center::db::crypto_expr::update_signing_key_private_key(&db, PRIVATE, key)
        .await
        .unwrap();
    let password =
        user_center::service::password::PasswordIdentityService::hash_password("OriginalPass123!")
            .await
            .unwrap();
    user_center::service::password::PasswordIdentityService::create_hashed(
        &db,
        user,
        provider,
        user.to_string(),
        password,
        time::OffsetDateTime::now_utc(),
    )
    .await
    .unwrap();
    let (app_a, app_b, client_a, client_b) = (
        Uuid::now_v7(),
        Uuid::now_v7(),
        Uuid::now_v7(),
        Uuid::now_v7(),
    );
    for (app, client, name) in [
        (app_a, client_a, "admin-client"),
        (app_b, client_b, "other-client"),
    ] {
        sql(
            &db,
            "INSERT INTO apps(id,code,name) VALUES($1,$2,$2)",
            vec![app.into(), name.into()],
        )
        .await;
        sql(&db,"INSERT INTO oauth_clients(id,app_id,identifier,secret_hash,type,redirect_uris,scopes,require_pkce) VALUES($1,$2,$3,'test-hash','confidential',ARRAY['https://client.example.test/callback'],ARRAY['openid']::text[],false)",vec![client.into(),app.into(),name.into()]).await;
        sql(
            &db,
            "INSERT INTO user_app_access(user_id,app_id) VALUES($1,$2)",
            vec![user.into(), app.into()],
        )
        .await;
    }
    let (raw_old, sid_old) = state
        .session_service()
        .create(user, None, None, None, None)
        .await
        .unwrap();
    let old_at = jwt(&issuer, user, "admin-client", sid_old, Some("openid"), None);
    // Authorize max_age=0 using a minute-old session and existing consent.
    sql(
        &db,
        "UPDATE sso_sessions SET authenticated_at=now()-interval '60 seconds' WHERE id=$1",
        vec![sid_old.into()],
    )
    .await;
    sql(
        &db,
        "INSERT INTO user_consents(user_id,client_id,scopes) VALUES($1,$2,ARRAY['openid']::text[])",
        vec![user.into(), client_a.into()],
    )
    .await;
    let app = user_center::router::build(state.clone());
    for (age, expected) in [
        (0, "error=login_required"),
        (30, "error=login_required"),
        (120, "code="),
    ] {
        let uri = format!(
            "/oauth2/authorize?client_id=admin-client&redirect_uri=https%3A%2F%2Fclient.example.test%2Fcallback&response_type=code&scope=openid&prompt=none&max_age={age}"
        );
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(uri)
                    .header("cookie", format!("pero_sso={raw_old}"))
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let location = response
            .headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(
            location.starts_with(&format!("https://client.example.test/callback?{expected}")),
            "{location}"
        );
    }
    let selection=app.clone().oneshot(Request::builder().uri("/oauth2/authorize?client_id=admin-client&redirect_uri=https%3A%2F%2Fclient.example.test%2Fcallback&response_type=code&scope=openid&prompt=select_account").header("cookie",format!("pero_sso={raw_old}")).body(axum::body::Body::empty()).unwrap()).await.unwrap();
    assert!(
        selection.headers()["location"]
            .to_str()
            .unwrap()
            .contains("error=invalid_request")
    );
    assert!(
        pero_utils::oauth::jwt::verify_id_token(&old_at, &issuer, "admin-client", PUBLIC).is_err()
    );
    // Contact replacement invalidates previously issued recovery credentials and pending messages.
    let reset = pero_utils::oauth::jwt::sign_password_reset_token(
        &user.to_string(),
        3600,
        state.config.password_reset.signing_key.expose_secret(),
    )
    .unwrap();
    sql(&db,"INSERT INTO password_reset_tokens(user_id,token_hash,expires_at) VALUES($1,$2,now()+interval '1 hour')",vec![user.into(),pero_utils::crypto::sha256_hex(&reset).into()]).await;
    user_center::service::notify::enqueue(
        &db,
        user,
        &user_center::service::notify::Notification {
            channel: "email",
            kind: "reset_password",
            to: "old@example.test",
            code: None,
            link: "https://issuer.example.test/reset",
        },
        time::OffsetDateTime::now_utc() + time::Duration::hours(1),
    )
    .await
    .unwrap();
    let (jar, csrf_token) = state.web_security().ensure_csrf(CookieJar::new());
    let form = user_center::web::dashboard::template::UserFormData {
        csrf_token,
        username: "review_user".into(),
        email: "new@example.test".into(),
        ..Default::default()
    };
    let response = user_center::web::dashboard::users::update(
        State(state.clone()),
        jar,
        Path(user),
        Form(form),
    )
    .await;
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&body).unwrap()["code"],
        0
    );
    let result = user_center::service::account::AccountService::new(&state)
        .reset_password(&reset, "ChangedPass456!", "ChangedPass456!")
        .await;
    assert!(result.is_err());
    let queued = db
        .query_one_raw(Statement::from_string(
            DbBackend::Postgres,
            "SELECT count(*) AS n FROM notification_outbox".to_owned(),
        ))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(queued.try_get::<i64>("", "n").unwrap(), 0);
    // Use a fresh pool for each DDL fault so cached plans cannot bind to public fallback tables.
    for table in [
        "identity_provider_keys",
        "oauth_clients",
        "users",
        "apps",
        "user_app_access",
        "sso_sessions",
    ] {
        // Renaming inside the isolated schema exposes the empty baseline table in public.
        // Instead remove public from the test connection's search path: missing tables must error.
        let mut config = (*state.config).clone();
        let mut url = url::Url::parse(config.database.url.expose_secret()).unwrap();
        let options = url
            .query_pairs()
            .find(|(k, _)| k == "options")
            .unwrap()
            .1
            .replace(",public", "");
        url.set_query(None);
        url.query_pairs_mut().append_pair("options", &options);
        config.database.url = serde_json::from_value(serde_json::json!(url.as_str())).unwrap();
        let (fault_db, fault_guard) = user_center::db::init::init_db(&config).await.unwrap();
        let cache = pero_cache_redis::RedisCacheStore::from_config(&config.redis).unwrap();
        let http =
            pero_http_client_reqwest::ReqwestHttpClient::from_config(&config.http_config).unwrap();
        let fault_state = user_center::state::app::AppState::new(config, fault_db, cache, http);
        sql(
            &db,
            &format!("ALTER TABLE {table} RENAME TO unavailable_{table}"),
            vec![],
        )
        .await;
        let response = user_center::api::userinfo::userinfo(State(fault_state), {
            let mut headers = axum::http::HeaderMap::new();
            headers.insert("authorization", format!("Bearer {old_at}").parse().unwrap());
            headers
        })
        .await;
        sql(
            &db,
            &format!("ALTER TABLE unavailable_{table} RENAME TO {table}"),
            vec![],
        )
        .await;
        fault_guard.shutdown().await;
        assert_eq!(
            response.status(),
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "{table}"
        );
    }
    guard.shutdown().await;
    // Dependency failure must neither redirect to login nor clear a valid cookie.
    let response = app
        .oneshot(
            Request::builder()
                .uri("/account/profile")
                .header("cookie", format!("pero_sso={raw_old}"))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        axum::http::StatusCode::SERVICE_UNAVAILABLE
    );
    assert!(!response.headers().contains_key("set-cookie"));
    fixture.cleanup().await;
}
