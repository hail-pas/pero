#[path = "support/database.rs"]
mod database;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::Request,
};
use serde_json::Value;
use tower::ServiceExt;
use user_center::{config::AppConfig, service::security::execute, state::app::AppState};
use uuid::Uuid;

async fn request(app: &Router, cookie: &str, path: &str, body: Option<String>) -> Value {
    let req = if let Some(body) = body {
        Request::post(path)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap()
    } else {
        Request::get(path).body(Body::empty()).unwrap()
    };
    let (mut parts, body) = req.into_parts();
    parts.headers.insert("cookie", cookie.parse().unwrap());
    parts
        .headers
        .insert("accept", "application/json".parse().unwrap());
    let response = app
        .clone()
        .oneshot(Request::from_parts(parts, body))
        .await
        .unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    serde_json::from_slice(&body)
        .unwrap_or_else(|_| panic!("{status}: {}", String::from_utf8_lossy(&body)))
}

#[tokio::test]
#[ignore = "requires dedicated PERO_TEST_DATABASE_URL and PERO_TEST_REDIS_URL"]
async fn denied_authorization_can_retry_switch_cancel_and_expire_safely() {
    let fixture = database::DatabaseFixture::new().await;
    let cfg: AppConfig = serde_json::from_value(serde_json::json!({
        "database":{"url":fixture.url,"encrypt_key":"access-recovery-test-key","min_connections":1},
        "redis":{"url":std::env::var("PERO_TEST_REDIS_URL").unwrap()},
        "sso":{"cookie_signing_secret":"access-recovery-test-signing-secret-long-enough"}
    }))
    .unwrap();
    let (db, guard) = user_center::db::init::init_db(&cfg).await.unwrap();
    fixture.migrate(&db).await;
    let cache = pero_cache_redis::RedisCacheStore::from_config(&cfg.redis).unwrap();
    let http = pero_http_client_reqwest::ReqwestHttpClient::from_config(&cfg.http_config).unwrap();
    let state = AppState::new(cfg, db.clone(), cache, http);
    let (user, application, client) = (Uuid::now_v7(), Uuid::now_v7(), Uuid::now_v7());
    execute(
        &db,
        "INSERT INTO users(id,username) VALUES($1,'recovery-member')",
        vec![user.into()],
    )
    .await
    .unwrap();
    execute(
        &db,
        "INSERT INTO apps(id,code,name) VALUES($1,'recovery-app','Recovery App')",
        vec![application.into()],
    )
    .await
    .unwrap();
    execute(&db,"INSERT INTO oauth_clients(id,app_id,identifier,type,redirect_uris,scopes,require_pkce) VALUES($1,$2,'recovery-client','public',ARRAY['com.example.app:/callback'],ARRAY['openid'],true)",vec![client.into(),application.into()]).await.unwrap();
    let (raw, sid) = state
        .session_service()
        .create(user, None, None, None, None)
        .await
        .unwrap();
    execute(
        &db,
        "UPDATE sso_sessions SET mfa_verified_at=now() WHERE id=$1",
        vec![sid.into()],
    )
    .await
    .unwrap();
    let jar = axum_extra::extract::CookieJar::new().add(axum_extra::extract::cookie::Cookie::new(
        "pero_sso",
        raw.clone(),
    ));
    let (_, csrf) = state.web_security().ensure_csrf(jar);
    let cookie = format!("pero_sso={raw}; pero_csrf={csrf}");
    let app = user_center::router::build(state.clone());
    let pkce = pero_utils::oauth::pkce::PkcePair::generate();
    let start = format!(
        "/oauth2/authorize?client_id=recovery-client&redirect_uri=com.example.app%3A%2Fcallback&response_type=code&scope=openid&state=preserved-state&nonce=preserved-nonce&code_challenge_method=S256&code_challenge={}",
        pkce.code_challenge
    );
    // Scope permission belongs to the client, independently of application membership.
    let invalid_scope = request(
        &app,
        &cookie,
        &start.replace("scope=openid", "scope=openid%20profile"),
        None,
    )
    .await;
    let callback = url::Url::parse(invalid_scope["redirect"].as_str().unwrap()).unwrap();
    assert!(
        callback
            .query_pairs()
            .any(|(k, v)| k == "error" && v == "invalid_scope")
    );
    assert!(callback.query_pairs().any(|(k, v)| k == "error_description"
        && v == "Requested scopes are not allowed for this client: profile"));
    assert!(
        callback
            .query_pairs()
            .any(|(k, v)| k == "state" && v == "preserved-state")
    );
    let initial = request(&app, &cookie, &start, None).await;
    let recovery = initial["redirect"].as_str().unwrap();
    assert!(recovery.starts_with("/oauth2/authorize/access?token="));
    let view = request(&app, &cookie, recovery, None).await;
    assert_eq!(view["view"], "AppAccessDeniedView");
    assert_eq!(view["data"]["app_name"], "Recovery App");
    let token = view["data"]["token"].as_str().unwrap();
    let form = |action: &str| {
        url::form_urlencoded::Serializer::new(String::new())
            .append_pair("csrf_token", &csrf)
            .append_pair("token", token)
            .append_pair("action", action)
            .finish()
    };
    let retry = request(
        &app,
        &cookie,
        "/oauth2/authorize/access",
        Some(form("retry")),
    )
    .await;
    assert!(
        retry["redirect"]
            .as_str()
            .unwrap()
            .starts_with("/oauth2/authorize/access?")
    );
    let invalid = request(
        &app,
        &cookie,
        "/oauth2/authorize/access",
        Some(format!("token={token}&action=cancel&csrf_token=wrong")),
    )
    .await;
    assert_eq!(invalid["error"], "invalid_csrf");
    let tampered = request(&app, &cookie, &format!("{recovery}tampered"), None).await;
    assert_eq!(tampered["data"]["expired"], true);
    // Silent authorization still sends the protocol error and original state to the client.
    let silent = request(&app, &cookie, &format!("{start}&prompt=none"), None).await;
    let silent_url = url::Url::parse(silent["redirect"].as_str().unwrap()).unwrap();
    assert!(
        silent_url
            .query_pairs()
            .any(|(k, v)| k == "error" && v == "access_denied")
    );
    assert!(
        silent_url
            .query_pairs()
            .any(|(k, v)| k == "state" && v == "preserved-state")
    );
    execute(
        &db,
        "INSERT INTO user_app_access(user_id,app_id) VALUES($1,$2)",
        vec![user.into(), application.into()],
    )
    .await
    .unwrap();
    let approved = request(
        &app,
        &cookie,
        "/oauth2/authorize/access",
        Some(form("retry")),
    )
    .await;
    assert_eq!(approved["redirect"], "/sso/consent");
    execute(
        &db,
        "INSERT INTO user_consents(user_id,client_id,scopes) VALUES($1,$2,ARRAY['openid'])",
        vec![user.into(), client.into()],
    )
    .await
    .unwrap();
    let completed = request(
        &app,
        &cookie,
        "/oauth2/authorize/access",
        Some(form("retry")),
    )
    .await;
    let callback = url::Url::parse(completed["redirect"].as_str().unwrap()).unwrap();
    assert_eq!(callback.scheme(), "com.example.app");
    assert_eq!(callback.path(), "/callback");
    assert!(
        callback
            .query_pairs()
            .any(|(k, v)| k == "code" && !v.is_empty())
    );
    assert!(
        callback
            .query_pairs()
            .any(|(k, v)| k == "state" && v == "preserved-state")
    );
    assert_eq!(
        request(&app, &cookie, recovery, None).await["data"]["expired"],
        true
    );
    execute(
        &db,
        "DELETE FROM user_app_access WHERE user_id=$1 AND app_id=$2",
        vec![user.into(), application.into()],
    )
    .await
    .unwrap();
    let cancel_start = request(&app, &cookie, &start, None).await;
    let recovery = cancel_start["redirect"].as_str().unwrap();
    let view = request(&app, &cookie, recovery, None).await;
    let cancel_form = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("csrf_token", &csrf)
        .append_pair("token", view["data"]["token"].as_str().unwrap())
        .append_pair("action", "cancel")
        .finish();
    // Cancellation ends the stored request and cannot later resume it.
    let cancelled = request(&app, &cookie, "/oauth2/authorize/access", Some(cancel_form)).await;
    assert_eq!(cancelled["redirect"], "/account/profile");
    assert_eq!(
        request(&app, &cookie, recovery, None).await["data"]["expired"],
        true
    );
    execute(
        &db,
        "DELETE FROM user_app_access WHERE user_id=$1 AND app_id=$2",
        vec![user.into(), application.into()],
    )
    .await
    .unwrap();
    let next = request(&app, &cookie, &start, None).await;
    let next = next["redirect"].as_str().unwrap();
    let view = request(&app, &cookie, next, None).await;
    let expired_form = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("csrf_token", &csrf)
        .append_pair("token", view["data"]["token"].as_str().unwrap())
        .append_pair("action", "retry")
        .finish();
    execute(&db,"UPDATE authorization_requests SET created_at=now()-interval '10 minutes', expires_at=now()-interval '1 second' WHERE completed_at IS NULL",vec![]).await.unwrap();
    assert_eq!(
        request(&app, &cookie, next, None).await["data"]["expired"],
        true
    );
    assert_eq!(
        request(
            &app,
            &cookie,
            "/oauth2/authorize/access",
            Some(expired_form)
        )
        .await["data"]["expired"],
        true
    );
    // A request for another account's workspace still permits switching identity.
    let other_user = Uuid::now_v7();
    execute(
        &db,
        "INSERT INTO users(id,username) VALUES($1,'other-recovery-member')",
        vec![other_user.into()],
    )
    .await
    .unwrap();
    use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
    use user_center::db::entity::tenants;
    let workspace = tenants::Entity::find()
        .filter(tenants::Column::OwnerUserId.eq(other_user))
        .one(&db)
        .await
        .unwrap()
        .unwrap();
    let next = request(
        &app,
        &cookie,
        &format!("{start}&tenant_id={}", workspace.id),
        None,
    )
    .await;
    let next = next["redirect"].as_str().unwrap();
    let view = request(&app, &cookie, next, None).await;
    assert_eq!(view["data"]["tenant_unavailable"], true);
    assert_eq!(view["data"]["can_request"], false);
    let switch_form = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("csrf_token", &csrf)
        .append_pair("token", view["data"]["token"].as_str().unwrap())
        .append_pair("action", "other")
        .finish();
    let switched = request(&app, &cookie, "/oauth2/authorize/access", Some(switch_form)).await;
    assert_eq!(switched["redirect"], "/sso/login");
    assert_eq!(
        request(&app, &cookie, next, None).await["data"]["expired"],
        true
    );
    db.close().await.unwrap();
    drop(guard);
    fixture.cleanup().await;
}

#[tokio::test]
#[ignore = "requires dedicated PERO_TEST_DATABASE_URL and PERO_TEST_REDIS_URL"]
async fn oauth_never_restores_super_admin_access_and_system_apps_require_mfa() {
    use sea_orm::EntityTrait;
    use user_center::db::{entity::user_app_access, enums::CommonStatus};
    let fixture = database::DatabaseFixture::new().await;
    let cfg: AppConfig = serde_json::from_value(serde_json::json!({
        "database":{"url":fixture.url,"encrypt_key":"auto-grant-test-key","min_connections":1},
        "redis":{"url":std::env::var("PERO_TEST_REDIS_URL").unwrap()},
        "sso":{"cookie_signing_secret":"auto-grant-test-signing-secret-long-enough"}
    }))
    .unwrap();
    let (db, guard) = user_center::db::init::init_db(&cfg).await.unwrap();
    fixture.migrate(&db).await;
    let cache = pero_cache_redis::RedisCacheStore::from_config(&cfg.redis).unwrap();
    let http = pero_http_client_reqwest::ReqwestHttpClient::from_config(&cfg.http_config).unwrap();
    let state = AppState::new(cfg, db.clone(), cache, http);
    let (user, application, client) = (Uuid::now_v7(), Uuid::now_v7(), Uuid::now_v7());
    execute(
        &db,
        "INSERT INTO users(id,username) VALUES($1,'auto-grant-admin')",
        vec![user.into()],
    )
    .await
    .unwrap();
    execute(
        &db,
        "INSERT INTO admin_roles(user_id,role) VALUES($1,'admin')",
        vec![user.into()],
    )
    .await
    .unwrap();
    execute(
        &db,
        "INSERT INTO apps(id,code,name) VALUES($1,'auto-grant-app','Auto grant app')",
        vec![application.into()],
    )
    .await
    .unwrap();
    execute(&db,"INSERT INTO oauth_clients(id,app_id,identifier,secret_hash,type,redirect_uris,scopes,require_pkce) VALUES($1,$2,'auto-grant-client','hash','confidential',ARRAY['https://client.example.test/callback'],ARRAY['openid'],false)",vec![client.into(),application.into()]).await.unwrap();
    let (raw, sid) = state
        .session_service()
        .create(user, None, None, None, None)
        .await
        .unwrap();
    let cookie = format!("pero_sso={raw}");
    let app = user_center::router::build(state.clone());
    let start = "/oauth2/authorize?client_id=auto-grant-client&redirect_uri=https%3A%2F%2Fclient.example.test%2Fcallback&response_type=code&scope=openid&state=auto-grant-state";
    // A delegated administrator still uses the access recovery page.
    let denied = request(&app, &cookie, start, None).await;
    assert!(
        denied["redirect"]
            .as_str()
            .unwrap()
            .starts_with("/oauth2/authorize/access?")
    );
    assert!(
        user_app_access::Entity::find_by_id((user, application))
            .one(&db)
            .await
            .unwrap()
            .is_none()
    );
    execute(
        &db,
        "UPDATE admin_roles SET role='super_admin' WHERE user_id=$1",
        vec![user.into()],
    )
    .await
    .unwrap();
    for system in [false, true] {
        execute(
            &db,
            "UPDATE apps SET system=$2 WHERE id=$1",
            vec![application.into(), system.into()],
        )
        .await
        .unwrap();
        let denied = request(&app, &cookie, start, None).await;
        assert!(
            denied["redirect"]
                .as_str()
                .unwrap()
                .starts_with("/oauth2/authorize/access?")
        );
        let silent = request(&app, &cookie, &format!("{start}&prompt=none"), None).await;
        assert!(
            silent["redirect"]
                .as_str()
                .unwrap()
                .contains("error=access_denied")
        );
        assert!(
            user_app_access::Entity::find_by_id((user, application))
                .one(&db)
                .await
                .unwrap()
                .is_none()
        );
    }
    let administrator = database::management_actor(&db).await;
    user_center::service::access::grant_app(&db, &administrator, user, application)
        .await
        .unwrap();
    let mfa = request(&app, &cookie, start, None).await;
    assert!(
        mfa["redirect"]
            .as_str()
            .unwrap()
            .starts_with("/account/security?")
    );
    execute(
        &db,
        "UPDATE sso_sessions SET mfa_verified_at=now() WHERE id=$1",
        vec![sid.into()],
    )
    .await
    .unwrap();
    assert_eq!(
        request(&app, &cookie, start, None).await["redirect"],
        "/sso/consent"
    );
    user_center::service::access::revoke_app(&db, &administrator, user, application)
        .await
        .unwrap();
    let denied = request(&app, &cookie, start, None).await;
    assert!(
        denied["redirect"]
            .as_str()
            .unwrap()
            .starts_with("/oauth2/authorize/access?")
    );
    let access = user_app_access::Entity::find_by_id((user, application))
        .one(&db)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(access.status, CommonStatus::Disabled);
    assert!(access.token_version > 0);
    db.close().await.unwrap();
    drop(guard);
    fixture.cleanup().await;
}
