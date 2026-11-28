#[path = "support/database.rs"]
mod database;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{HeaderMap, Request, header::SET_COOKIE},
};
use sea_orm::{ConnectionTrait, DatabaseConnection, DbBackend, Statement, TransactionTrait};
use serde_json::Value;
use std::time::Duration;
use tower::ServiceExt;
use user_center::{config::AppConfig, service::security::execute, state::app::AppState};
use uuid::Uuid;

async fn request(app: &Router, cookie: &str, path: &str, body: Option<String>) -> Value {
    request_with_headers(app, cookie, path, body).await.0
}

async fn request_with_headers(
    app: &Router,
    cookie: &str,
    path: &str,
    body: Option<String>,
) -> (Value, HeaderMap) {
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
    let headers = response.headers().clone();
    let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    let value = serde_json::from_slice(&body)
        .unwrap_or_else(|_| panic!("{status}: {}", String::from_utf8_lossy(&body)));
    (value, headers)
}

fn cookie_pair<'a>(headers: &'a HeaderMap, name: &str) -> &'a str {
    headers
        .get_all(SET_COOKIE)
        .iter()
        .filter_map(|header| header.to_str().ok())
        .filter_map(|header| header.split(';').next())
        .find(|pair| pair.split_once('=').is_some_and(|(key, _)| key == name))
        .unwrap()
}

async fn wait_for_lock(db: &DatabaseConnection, blocker: i32) -> i32 {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(row) = db
                .query_one_raw(Statement::from_sql_and_values(
                    DbBackend::Postgres,
                    "SELECT pid FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)) LIMIT 1",
                    [blocker.into()],
                ))
                .await
                .unwrap()
            {
                return row.try_get("", "pid").unwrap();
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("transaction waited for the expected database lock")
}

async fn consent_form(
    app: &Router,
    cookie: &str,
    (entry, headers): (Value, HeaderMap),
    action: &str,
) -> String {
    assert_eq!(entry["redirect"], "/sso/consent");
    let auth_cookie = cookie_pair(&headers, "pero_sso_req");
    let view = request(
        app,
        &format!("{cookie}; {auth_cookie}"),
        "/sso/consent",
        None,
    )
    .await;
    url::form_urlencoded::Serializer::new(String::new())
        .append_pair("csrf_token", view["data"]["csrf_token"].as_str().unwrap())
        .append_pair(
            "request_token",
            view["data"]["request_token"].as_str().unwrap(),
        )
        .append_pair("action", action)
        .finish()
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
        "INSERT INTO apps(id,code,name,tenant_mode) VALUES($1,'recovery-app','Recovery App','both')",
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
    let workspace = Uuid::now_v7();
    execute(
        &db,
        "INSERT INTO tenants(id,kind,name,slug,created_by)
         VALUES($1,'organization','Other Workspace','other-workspace',$2)",
        vec![workspace.into(), other_user.into()],
    )
    .await
    .unwrap();
    execute(
        &db,
        "INSERT INTO tenant_members(tenant_id,user_id,role) VALUES($1,$2,'owner')",
        vec![workspace.into(), other_user.into()],
    )
    .await
    .unwrap();
    let next = request(
        &app,
        &cookie,
        &format!("{start}&tenant_id={workspace}&prompt=consent"),
        None,
    )
    .await;
    let next = next["redirect"].as_str().unwrap();
    let view = request(&app, &cookie, next, None).await;
    assert_eq!(view["data"]["tenant_unavailable"], true);
    assert_eq!(view["data"]["can_request"], false);
    let form = |action: &str| {
        url::form_urlencoded::Serializer::new(String::new())
            .append_pair("csrf_token", &csrf)
            .append_pair("token", view["data"]["token"].as_str().unwrap())
            .append_pair("action", action)
            .finish()
    };
    execute(
        &db,
        "INSERT INTO tenant_members(tenant_id,user_id,role) VALUES($1,$2,'member')",
        vec![workspace.into(), user.into()],
    )
    .await
    .unwrap();
    execute(
        &db,
        "INSERT INTO user_app_access(user_id,app_id) VALUES($1,$3),($2,$3)",
        vec![user.into(), other_user.into(), application.into()],
    )
    .await
    .unwrap();
    let path = "/oauth2/authorize/access";
    let entry = request_with_headers(&app, &cookie, path, Some(form("retry"))).await;
    let deny = consent_form(&app, &cookie, entry, "deny").await;

    let blocker = db.begin().await.unwrap();
    let blocker_pid: i32 = blocker
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT pg_backend_pid() AS pid FROM authorization_requests
             WHERE client_id=$1 AND tenant_id=$2 AND completed_at IS NULL FOR UPDATE",
            [client.into(), workspace.into()],
        ))
        .await
        .unwrap()
        .unwrap()
        .try_get("", "pid")
        .unwrap();
    let switch = tokio::spawn({
        let (app, cookie, form) = (app.clone(), cookie.clone(), form("other"));
        async move { request_with_headers(&app, &cookie, path, Some(form)).await }
    });
    let switch_pid = wait_for_lock(&db, blocker_pid).await;
    let decline = tokio::spawn({
        let (app, cookie) = (app.clone(), cookie.clone());
        async move { request(&app, &cookie, "/sso/consent", Some(deny)).await }
    });
    wait_for_lock(&db, switch_pid).await;
    blocker.commit().await.unwrap();
    let (switched, headers) = switch.await.unwrap();
    assert_eq!(switched["redirect"], "/sso/login");
    assert_eq!(
        decline.await.unwrap()["redirect"],
        "/sso/error?code=invalid_request"
    );
    assert_eq!(
        request(&app, &cookie, next, None).await["data"]["expired"],
        true
    );
    let (other_raw, _) = state
        .session_service()
        .create(other_user, None, None, None, None)
        .await
        .unwrap();
    let resumed = request(
        &app,
        &format!(
            "pero_sso={other_raw}; {}",
            cookie_pair(&headers, "pero_sso_nonce")
        ),
        "/oauth2/authorize/resume",
        None,
    )
    .await;
    assert_eq!(resumed["redirect"], "/sso/consent");
    db.close().await.unwrap();
    drop(guard);
    fixture.cleanup().await;
}

#[tokio::test]
#[ignore = "requires dedicated PERO_TEST_DATABASE_URL and PERO_TEST_REDIS_URL"]
async fn oauth_opens_super_admin_access_once_and_system_apps_require_mfa() {
    use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
    use user_center::db::{
        entity::{tenants, user_app_access},
        enums::CommonStatus,
    };

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
        "INSERT INTO apps(id,code,name,tenant_mode) VALUES($1,'auto-grant-app','Auto grant app','both')",
        vec![application.into()],
    )
    .await
    .unwrap();
    execute(&db,"INSERT INTO oauth_clients(id,app_id,identifier,secret_hash,type,redirect_uris,scopes,require_pkce,account_sync_enabled,account_sync_uri) VALUES($1,$2,'auto-grant-client','hash','confidential',ARRAY['https://client.example.test/callback'],ARRAY['openid'],false,true,'https://client.example.test/sync')",vec![client.into(),application.into()]).await.unwrap();
    let (raw, _) = state
        .session_service()
        .create(user, None, None, None, None)
        .await
        .unwrap();
    let jar = axum_extra::extract::cookie::CookieJar::new().add(
        axum_extra::extract::cookie::Cookie::new("pero_sso", raw.clone()),
    );
    let (_, csrf) = state.web_security().ensure_csrf(jar);
    let cookie = format!("pero_sso={raw}; pero_csrf={csrf}");
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
    let silent = request(&app, &cookie, &format!("{start}&prompt=none"), None).await;
    assert!(
        silent["redirect"]
            .as_str()
            .unwrap()
            .contains("error=access_denied")
    );
    execute(
        &db,
        "UPDATE apps SET tenant_mode='organization' WHERE id=$1",
        vec![application.into()],
    )
    .await
    .unwrap();
    let no_workspace = request(&app, &cookie, start, None).await;
    let choose_workspace = no_workspace["redirect"].as_str().unwrap();
    assert!(choose_workspace.starts_with("/oauth2/authorize/tenant?"));
    let empty = request(&app, &cookie, choose_workspace, None).await;
    assert_eq!(empty["view"], "TenantChoiceView");
    assert_eq!(empty["data"]["choices"], serde_json::json!([]));
    execute(
        &db,
        "UPDATE apps SET tenant_mode='both' WHERE id=$1",
        vec![application.into()],
    )
    .await
    .unwrap();
    let factor_secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    execute(
        &db,
        "INSERT INTO user_mfa(user_id,secret_enc,enabled)
         VALUES ($1,pgp_sym_encrypt($2,current_setting('app.encrypt_key')),true)",
        vec![user.into(), factor_secret.into()],
    )
    .await
    .unwrap();
    execute(
        &db,
        "INSERT INTO application_access_requests (id,user_id,app_id) VALUES ($1,$2,$3)",
        vec![Uuid::now_v7().into(), user.into(), application.into()],
    )
    .await
    .unwrap();
    let workspace = tenants::Entity::find()
        .filter(tenants::Column::OwnerUserId.eq(user))
        .one(&db)
        .await
        .unwrap()
        .unwrap();
    let organization = Uuid::now_v7();
    execute(
        &db,
        "INSERT INTO tenants(id,kind,name,slug) VALUES($1,'organization','OAuth Org','oauth-org')",
        vec![organization.into()],
    )
    .await
    .unwrap();
    execute(
        &db,
        "INSERT INTO tenant_members(tenant_id,user_id,role) VALUES($1,$2,'owner')",
        vec![organization.into(), user.into()],
    )
    .await
    .unwrap();
    let (challenge, headers) = request_with_headers(&app, &cookie, start, None).await;
    let resume = "/oauth2/authorize/resume";
    assert_eq!(
        challenge["redirect"],
        "/sso/mfa?redirect=%2Foauth2%2Fauthorize%2Fresume"
    );
    let pending_cookie = cookie_pair(&headers, "pero_sso_nonce");
    let code = user_center::service::security::totp(factor_secret, "auto-grant-admin")
        .unwrap()
        .generate(time::OffsetDateTime::now_utc().unix_timestamp() as u64)
        .to_string();
    let form = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("csrf_token", &csrf)
        .append_pair("action", "verify")
        .append_pair("code", &code)
        .append_pair("redirect", resume)
        .finish();
    let (verified, headers) = request_with_headers(&app, &cookie, "/sso/mfa", Some(form)).await;
    assert_eq!(verified["redirect"], resume);
    let session_cookie = cookie_pair(&headers, "pero_sso");
    let entry = request(
        &app,
        &format!("{session_cookie}; {pending_cookie}"),
        resume,
        None,
    )
    .await;
    let choose = entry["redirect"].as_str().unwrap();
    assert!(choose.starts_with("/oauth2/authorize/tenant?"));
    let (view, headers) = request_with_headers(&app, session_cookie, choose, None).await;
    let cookie = format!("{session_cookie}; {}", cookie_pair(&headers, "pero_csrf"));
    assert_eq!(view["data"]["choices"].as_array().unwrap().len(), 2);
    let choice = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("csrf_token", view["data"]["csrf_token"].as_str().unwrap())
        .append_pair("token", view["data"]["token"].as_str().unwrap())
        .append_pair("tenant_id", &workspace.id.to_string())
        .finish();
    let policy_change = db.begin().await.unwrap();
    let policy_pid: i32 = policy_change
        .query_one_raw(Statement::from_string(
            DbBackend::Postgres,
            "SELECT pg_backend_pid() AS pid",
        ))
        .await
        .unwrap()
        .unwrap()
        .try_get("", "pid")
        .unwrap();
    execute(
        &policy_change,
        "UPDATE oauth_clients SET status='disabled' WHERE id=$1",
        vec![client.into()],
    )
    .await
    .unwrap();
    let (choice_app, choice_cookie, blocked_choice) = (app.clone(), cookie.clone(), choice.clone());
    let selection = tokio::spawn(async move {
        request(
            &choice_app,
            &choice_cookie,
            "/oauth2/authorize/tenant",
            Some(blocked_choice),
        )
        .await
    });
    wait_for_lock(&db, policy_pid).await;
    policy_change.commit().await.unwrap();
    assert_eq!(selection.await.unwrap()["error"], "invalid_request");
    execute(
        &db,
        "UPDATE oauth_clients SET status='active' WHERE id=$1",
        vec![client.into()],
    )
    .await
    .unwrap();
    let entry = request_with_headers(&app, &cookie, "/oauth2/authorize/tenant", Some(choice)).await;
    let deny = consent_form(&app, &cookie, entry, "deny").await;
    assert!(
        user_app_access::Entity::find_by_id((user, application))
            .one(&db)
            .await
            .unwrap()
            .is_none()
    );
    let policy_change = db.begin().await.unwrap();
    let policy_pid: i32 = policy_change
        .query_one_raw(Statement::from_string(
            DbBackend::Postgres,
            "SELECT pg_backend_pid() AS pid",
        ))
        .await
        .unwrap()
        .unwrap()
        .try_get("", "pid")
        .unwrap();
    execute(
        &policy_change,
        "UPDATE oauth_clients SET redirect_uris=ARRAY['https://client.example.test/new-callback'] WHERE id=$1",
        vec![client.into()],
    )
    .await
    .unwrap();
    let (deny_app, deny_cookie, deny_form) = (app.clone(), cookie.clone(), deny.clone());
    let denial = tokio::spawn(async move {
        request(&deny_app, &deny_cookie, "/sso/consent", Some(deny_form)).await
    });
    wait_for_lock(&db, policy_pid).await;
    policy_change.commit().await.unwrap();
    assert_eq!(
        denial.await.unwrap()["redirect"],
        "/sso/error?code=invalid_request"
    );
    execute(
        &db,
        "UPDATE oauth_clients SET redirect_uris=ARRAY['https://client.example.test/callback'] WHERE id=$1",
        vec![client.into()],
    )
    .await
    .unwrap();
    let rejected = request(&app, &cookie, "/sso/consent", Some(deny)).await;
    assert!(
        rejected["redirect"]
            .as_str()
            .unwrap()
            .contains("error=access_denied")
    );
    assert_eq!(
        user_center::service::application_request::current(&db, user, application)
            .await
            .unwrap()
            .unwrap()
            .status,
        "pending"
    );
    let in_workspace = format!("{start}&tenant_id={}", workspace.id);
    let entry = request_with_headers(&app, &cookie, &in_workspace, None).await;
    let allow = consent_form(&app, &cookie, entry, "allow").await;
    let session = state
        .session_service()
        .validate(session_cookie.split_once('=').unwrap().1)
        .await
        .unwrap()
        .unwrap();
    let sid = session.id;
    execute(
        &db,
        "UPDATE sso_sessions SET mfa_verified_at=NULL WHERE id=$1",
        vec![sid.into()],
    )
    .await
    .unwrap();
    let unverified = request(&app, &cookie, "/sso/consent", Some(allow.clone())).await;
    assert_eq!(unverified["redirect"], "/sso/error?code=invalid_request");
    assert!(
        user_app_access::Entity::find_by_id((user, application))
            .one(&db)
            .await
            .unwrap()
            .is_none()
    );
    execute(
        &db,
        "UPDATE sso_sessions SET mfa_verified_at=now() WHERE id=$1",
        vec![sid.into()],
    )
    .await
    .unwrap();
    execute(
        &db,
        "UPDATE registration_policies SET emergency_stop=true WHERE app_id IS NULL",
        vec![],
    )
    .await
    .unwrap();
    let paused = request(&app, &cookie, "/sso/consent", Some(allow.clone())).await;
    assert_eq!(paused["redirect"], "/sso/error?code=invalid_request");
    assert!(
        user_app_access::Entity::find_by_id((user, application))
            .one(&db)
            .await
            .unwrap()
            .is_none()
    );
    execute(
        &db,
        "UPDATE registration_policies SET emergency_stop=false WHERE app_id IS NULL",
        vec![],
    )
    .await
    .unwrap();
    user_center::service::tenant::set_status(&db, user, organization, "disabled")
        .await
        .unwrap();
    // Pause approval after it writes the access row, then reactivate another eligible workspace.
    let blocker = db.begin().await.unwrap();
    let blocker_pid: i32 = blocker
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT pg_backend_pid() AS pid FROM authorization_requests
         WHERE client_id=$1 AND tenant_id=$2 AND completed_at IS NULL FOR UPDATE",
            [client.into(), workspace.id.into()],
        ))
        .await
        .unwrap()
        .unwrap()
        .try_get("", "pid")
        .unwrap();
    let approval_app = app.clone();
    let approval_cookie = cookie.clone();
    let approval = tokio::spawn(async move {
        request(&approval_app, &approval_cookie, "/sso/consent", Some(allow)).await
    });
    let approval_pid = wait_for_lock(&db, blocker_pid).await;
    let tenant_db = db.clone();
    let activation = tokio::spawn(async move {
        user_center::service::tenant::set_status(&tenant_db, user, organization, "active").await
    });
    wait_for_lock(&db, approval_pid).await;
    blocker.commit().await.unwrap();
    let allowed = approval.await.unwrap();
    activation.await.unwrap().unwrap();
    assert!(allowed["redirect"].as_str().unwrap().contains("code="));
    assert!(
        db.query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT 1 FROM account_sync_deliveries
         WHERE client_id=$1 AND user_id=$2 AND tenant_id=$3 AND kind='tenant.membership.changed'",
            [client.into(), user.into(), organization.into()],
        ))
        .await
        .unwrap()
        .is_some()
    );
    let access = user_app_access::Entity::find_by_id((user, application))
        .one(&db)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(access.status, CommonStatus::Active);
    assert_eq!(access.admission_origin, "explicit");
    assert_eq!(
        user_center::service::application_request::current(&db, user, application)
            .await
            .unwrap()
            .unwrap()
            .status,
        "approved"
    );
    execute(
        &db,
        "UPDATE sso_sessions SET mfa_verified_at=NULL WHERE id=$1",
        vec![sid.into()],
    )
    .await
    .unwrap();
    assert!(
        request(&app, &cookie, &in_workspace, None).await["redirect"]
            .as_str()
            .unwrap()
            .contains("code=")
    );

    let administrator = database::management_actor(&db).await;
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

    execute(
        &db,
        "DELETE FROM user_app_access WHERE user_id=$1 AND app_id=$2",
        vec![user.into(), application.into()],
    )
    .await
    .unwrap();
    execute(
        &db,
        "UPDATE apps SET system=true WHERE id=$1",
        vec![application.into()],
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
    user_center::service::access::grant_app(&db, &administrator, user, application)
        .await
        .unwrap();
    let mfa = request(&app, &cookie, start, None).await;
    assert!(mfa["redirect"].as_str().unwrap().starts_with("/sso/mfa?"));
    execute(
        &db,
        "UPDATE sso_sessions SET mfa_verified_at=now() WHERE id=$1",
        vec![sid.into()],
    )
    .await
    .unwrap();
    for prompt in ["consent", "none"] {
        let invalid = request(
            &app,
            &cookie,
            &format!("{in_workspace}&prompt={prompt}"),
            None,
        )
        .await;
        let callback = url::Url::parse(invalid["redirect"].as_str().unwrap()).unwrap();
        let params: std::collections::HashMap<_, _> = callback.query_pairs().collect();
        assert_eq!(params["error"], "invalid_request");
        assert_eq!(params["state"], "auto-grant-state");
    }
    assert_eq!(
        request(&app, &cookie, &format!("{start}&prompt=consent"), None).await["redirect"],
        "/sso/consent"
    );
    db.close().await.unwrap();
    drop(guard);
    fixture.cleanup().await;
}
