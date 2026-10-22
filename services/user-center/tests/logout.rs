#[path = "support/database.rs"]
mod database;
use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
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
fn token(sub: Uuid, sid: Option<Uuid>, expired: bool) -> String {
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let claims = serde_json::json!({"iss":"https://issuer.test","sub":sub.to_string(),"aud":"logout-test","sid":sid.map(|s|s.to_string()),"iat":now-3600,"exp":if expired {now-120} else {now+3600}});
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some("logout-test".into());
    jsonwebtoken::encode(
        &header,
        &claims,
        &jsonwebtoken::EncodingKey::from_rsa_pem(PRIVATE.as_bytes()).unwrap(),
    )
    .unwrap()
}
fn params(jwt: &str) -> String {
    url::form_urlencoded::Serializer::new(String::new())
        .append_pair("id_token_hint", jwt)
        .append_pair("post_logout_redirect_uri", "https://rp.test/out?existing=1")
        .append_pair("state", "a&b+c")
        .finish()
}
fn hidden(html: &str, name: &str) -> String {
    html.split(&format!("name=\"{name}\" value=\""))
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap()
        .to_owned()
}
#[tokio::test]
#[ignore = "requires dedicated PERO_TEST_DATABASE_URL"]
async fn logout_confirmation_expiry_and_form_contract() {
    let fixture = database::DatabaseFixture::new().await;
    let cfg:user_center::config::AppConfig=serde_json::from_value(serde_json::json!({
        "database":{"url":fixture.url,"encrypt_key":"test-only-key","min_connections":1,"max_connections":8},
        "redis":{"url":std::env::var("PERO_TEST_REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:1".into()),"connect_timeout_secs":1,"command_timeout_secs":1},
        "sso":{"cookie_signing_secret":"test-only-cookie-secret-long-enough"},
        "oidc":{"issuer":"https://issuer.test"},"password_reset":{"signing_key":"test-only-reset-secret-long-enough"}
    })).unwrap();
    let (db, guard) = user_center::db::init::init_db(&cfg).await.unwrap();
    fixture.migrate(&db).await;
    let cache = pero_cache_redis::RedisCacheStore::from_config(&cfg.redis).unwrap();
    let http = pero_http_client_reqwest::ReqwestHttpClient::from_config(&cfg.http_config).unwrap();
    let state = user_center::state::app::AppState::new(cfg, db.clone(), cache, http);
    let (user, provider, app, client, key) = (
        Uuid::now_v7(),
        Uuid::now_v7(),
        Uuid::now_v7(),
        Uuid::now_v7(),
        Uuid::now_v7(),
    );
    sql(
        &db,
        "INSERT INTO users(id,username) VALUES($1,'logout_user')",
        vec![user.into()],
    )
    .await;
    sql(&db,"INSERT INTO identity_providers(id,code,name,kind,issuer) VALUES($1,'local','Local','local','https://issuer.test')",vec![provider.into()]).await;
    sql(&db,"INSERT INTO identity_provider_keys(id,provider_id,kid,public_key_pem,active) VALUES($1,$2,'logout-test',$3,true)",vec![key.into(),provider.into(),PUBLIC.into()]).await;
    sql(
        &db,
        "INSERT INTO apps(id,code,name) VALUES($1,'logout-test','Logout test')",
        vec![app.into()],
    )
    .await;
    sql(&db,"INSERT INTO oauth_clients(id,app_id,identifier,type,redirect_uris,post_logout_redirect_uris) VALUES($1,$2,'logout-test','public',ARRAY['https://rp.test/cb'],ARRAY['https://rp.test/out?existing=1'])",vec![client.into(),app.into()]).await;
    let router = user_center::router::build(state.clone());
    for mode in ["get", "expired_get", "post"] {
        let (raw, sid) = state
            .session_service()
            .create(user, None, None, None, None)
            .await
            .unwrap();
        let jwt = token(user, Some(sid), mode == "expired_get");
        if mode == "expired_get" {
            assert!(
                pero_utils::oauth::jwt::verify_id_token(
                    &jwt,
                    "https://issuer.test",
                    "logout-test",
                    PUBLIC
                )
                .is_err()
            );
        }
        let query = params(&jwt);
        let (uri, body) = if mode == "post" {
            ("/oauth2/session/end".to_owned(), Body::from(query))
        } else {
            (format!("/oauth2/session/end?{query}"), Body::empty())
        };
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method(if mode.contains("post") { "POST" } else { "GET" })
                    .uri(uri)
                    .header("cookie", format!("pero_sso={raw}"))
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(body)
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER, "{mode}");
        let location = url::Url::parse(response.headers()["location"].to_str().unwrap()).unwrap();
        assert!(
            location
                .query_pairs()
                .any(|(k, v)| k == "state" && v == "a&b+c")
        );
        assert!(
            state
                .session_service()
                .validate(&raw)
                .await
                .unwrap()
                .is_none()
        );
    }
    for mode in ["other_user", "other_session", "no_sid", "no_hint"] {
        let (raw, sid) = state
            .session_service()
            .create(user, None, None, None, None)
            .await
            .unwrap();
        let jwt = if mode == "no_hint" {
            String::new()
        } else {
            token(
                if mode == "other_user" {
                    Uuid::now_v7()
                } else {
                    user
                },
                if mode == "no_sid" {
                    None
                } else if mode == "other_session" {
                    Some(Uuid::now_v7())
                } else {
                    Some(sid)
                },
                false,
            )
        };
        let response = router
            .clone()
            .oneshot(
                Request::get(format!("/oauth2/session/end?{}", params(&jwt)))
                    .header("cookie", format!("pero_sso={raw}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let cookies = response
            .headers()
            .get_all("set-cookie")
            .iter()
            .map(|v| v.to_str().unwrap().split(';').next().unwrap().to_owned())
            .collect::<Vec<_>>()
            .join("; ");
        let html = String::from_utf8(
            to_bytes(response.into_body(), 1024 * 1024)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(!html.contains("您已成功退出登录"));
        assert!(html.contains("name=\"confirm\""));
        assert!(
            state
                .session_service()
                .validate(&raw)
                .await
                .unwrap()
                .is_some()
        );
        let form = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("confirm", "yes")
            .append_pair("csrf_token", &hidden(&html, "csrf_token"))
            .append_pair("session_id", &sid.to_string())
            .finish();
        let request = |cookie: String, form: String| {
            Request::post("/oauth2/session/end")
                .header("cookie", cookie)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(form))
                .unwrap()
        };
        let response = router
            .clone()
            .oneshot(request(format!("pero_sso={raw}"), form.clone()))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let (other, _) = state
            .session_service()
            .create(user, None, None, None, None)
            .await
            .unwrap();
        let response = router
            .clone()
            .oneshot(request(
                format!("pero_sso={other}; {cookies}"),
                form.clone(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let response = router
            .clone()
            .oneshot(request(format!("pero_sso={raw}; {cookies}"), form))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            state
                .session_service()
                .validate(&raw)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            state
                .session_service()
                .validate(&other)
                .await
                .unwrap()
                .is_some()
        );
    }
    // Missing route is a real HTTP 404, not merely a 404-looking page.
    assert_eq!(
        router
            .clone()
            .oneshot(Request::get("/missing").body(Body::empty()).unwrap())
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
    if std::env::var("PERO_BROWSER_TEST").as_deref() == Ok("1") {
        browser_flow(&state, router.clone(), user, provider).await;
    }
    // An unavailable signing-key database is not a successful or invalid logout.
    guard.shutdown().await;
    db.clone().close().await.unwrap();
    let response = router
        .oneshot(
            Request::get(format!(
                "/oauth2/session/end?{}",
                params(&token(user, None, false))
            ))
            .body(Body::empty())
            .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    fixture.cleanup().await;
}

async fn browser_flow(
    state: &user_center::state::app::AppState,
    router: axum::Router,
    user: Uuid,
    provider: Uuid,
) {
    let other = Uuid::now_v7();
    sql(
        &state.db,
        "INSERT INTO users(id,username) VALUES($1,'logout_other')",
        vec![other.into()],
    )
    .await;
    for id in [user, other] {
        user_center::service::password::PasswordIdentityService::create(
            &state.db,
            id,
            provider,
            id.to_string(),
            "BrowserTest123!",
            time::OffsetDateTime::now_utc(),
        )
        .await
        .unwrap();
    }
    let hint_state = state.clone();
    // Test-only endpoint on an ephemeral loopback server, never mounted by production.
    let router=router.route("/__test/logout-hints",axum::routing::get(move |jar: axum_extra::extract::CookieJar| {
        let state=hint_state.clone();
        async move {
            let raw=jar.get("pero_sso").unwrap().value();
            let session=state.session_service().validate(raw).await.unwrap().unwrap();
            axum::Json(serde_json::json!({"fresh":token(session.user_id,Some(session.id),false),"expired":token(session.user_id,Some(session.id),true)}))
        }
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await
        .unwrap()
    });
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(120),
        tokio::process::Command::new("node")
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../tests/browser/logout.cjs"
            ))
            .env("PERO_BROWSER_URL", base)
            .kill_on_drop(true)
            .output(),
    )
    .await;
    task.abort();
    let output = result.expect("browser timed out").expect("run browser");
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    eprintln!("{}", String::from_utf8_lossy(&output.stdout));
}
