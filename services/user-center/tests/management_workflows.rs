#[path = "support/database.rs"]
mod database;

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use axum_extra::extract::{CookieJar, cookie::Cookie};
use sea_orm::{ConnectionTrait, DbBackend, EntityTrait, Statement};
use serde_json::{Value, json};
use tower::ServiceExt;
use user_center::{config::AppConfig, state::app::AppState};
use uuid::Uuid;

struct Fixture {
    database: database::DatabaseFixture,
    guard: pero_db_seaorm::DatabaseGuard,
    state: AppState,
    admin: Uuid,
    user: Uuid,
    app: Uuid,
    client: Uuid,
    secret: String,
}
impl Fixture {
    async fn new() -> Self {
        let database = database::DatabaseFixture::new().await;
        let config:AppConfig=serde_json::from_value(json!({
            "database":{"url":database.url,"encrypt_key":"workflow-test-key","min_connections":1,"max_connections":8},
            "redis":{"url":std::env::var("PERO_TEST_REDIS_URL").unwrap()},
            "sso":{"cookie_signing_secret":"workflow-test-signing-key-long-enough","cookie_secure":false},
            "oidc":{"issuer":"https://issuer.example.test"},
            "notification":{"endpoint":"https://notifications.example.test"},
            "password_reset":{"signing_key":"workflow-test-reset-key-long-enough"}
        })).unwrap();
        let (db, guard) = user_center::db::init::init_db(&config).await.unwrap();
        database.migrate(&db).await;
        let state = AppState::new(
            config.clone(),
            db,
            pero_cache_redis::RedisCacheStore::from_config(&config.redis).unwrap(),
            pero_http_client_reqwest::ReqwestHttpClient::from_config(&config.http_config).unwrap(),
        );
        let f = Self {
            database,
            guard,
            state,
            admin: Uuid::now_v7(),
            user: Uuid::now_v7(),
            app: Uuid::now_v7(),
            client: Uuid::now_v7(),
            secret: "original-client-secret".into(),
        };
        f.sql("INSERT INTO users(id,username,email,email_verified_at) VALUES($1,'workflow_admin','admin@example.test',now()),($2,'workflow_user','member@example.test',now())",vec![f.admin.into(),f.user.into()]).await;
        f.sql(
            "INSERT INTO apps(id,code,name) VALUES($1,'workflow-app','Before')",
            vec![f.app.into()],
        )
        .await;
        f.sql("INSERT INTO oauth_clients(id,app_id,identifier,secret_hash,type,redirect_uris,scopes,require_pkce) VALUES($1,$2,$3,$4,'confidential',ARRAY['https://client.example.test/callback'],ARRAY['openid']::text[],false)",vec![f.client.into(),f.app.into(),f.client.to_string().into(),pero_utils::crypto::hash_secret_async(&f.secret).await.unwrap().into()]).await;
        let provider = Uuid::now_v7();
        f.sql("INSERT INTO identity_providers(id,code,name,kind,issuer) VALUES($1,'local','Local','local','https://issuer.example.test')",vec![provider.into()]).await;
        f.sql("INSERT INTO identity_provider_keys(provider_id,kid,public_key_pem,active) VALUES($1,'workflow-key',$2,true)",vec![provider.into(),include_str!("../../../tests/fixtures/rsa-public.pem").into()]).await;
        f.sql(
            "UPDATE registration_policies SET mode='self_service'",
            vec![],
        )
        .await;
        f
    }
    async fn sql(&self, q: &str, v: Vec<sea_orm::Value>) {
        self.state
            .db
            .execute_raw(Statement::from_sql_and_values(DbBackend::Postgres, q, v))
            .await
            .unwrap();
    }
    async fn login(&self, user: Uuid) -> (String, String, Uuid, String) {
        let (raw, id) = self
            .state
            .session_service()
            .create(user, None, None, None, Some("workflow-device".into()))
            .await
            .unwrap();
        let (jar, csrf) = self
            .state
            .web_security()
            .ensure_csrf(CookieJar::new().add(Cookie::new("pero_sso", raw.clone())));
        let cookies = jar
            .iter()
            .map(|c| format!("{}={}", c.name(), c.value()))
            .collect::<Vec<_>>()
            .join("; ");
        (cookies, csrf, id, raw)
    }
    async fn admin_login(&self) -> (String, String) {
        let (cookies, csrf, sid, _) = self.login(self.admin).await;
        self.sql(
            "INSERT INTO admin_roles(user_id,role) VALUES($1,'super_admin');",
            vec![self.admin.into()],
        )
        .await;
        self.sql("INSERT INTO user_mfa(user_id,secret_enc,enabled) VALUES($1,pgp_sym_encrypt('GEZDGNBVGY3TQOJQ',current_setting('app.encrypt_key')),true)",vec![self.admin.into()]).await;
        self.sql(
            "UPDATE sso_sessions SET mfa_required=true,mfa_verified_at=now() WHERE id=$1",
            vec![sid.into()],
        )
        .await;
        (cookies, csrf)
    }
    fn token(&self, sid: Uuid) -> String {
        let key = jsonwebtoken::EncodingKey::from_rsa_pem(include_bytes!(
            "../../../tests/fixtures/rsa-private.pem"
        ))
        .unwrap();
        pero_utils::oauth::jwt::sign_access_token_with_key(
            &pero_utils::oauth::jwt::AccessTokenParams {
                issuer: &self.state.config.oidc.issuer,
                user_id: &self.user.to_string(),
                client_identifier: &self.client.to_string(),
                scopes: "openid",
                client_version: 0,
                access_version: 0,
                ttl_seconds: 3600,
                session_id: Some(&sid.to_string()),
                kid: Some("workflow-key"),
            },
            &key,
        )
        .unwrap()
    }
    async fn cleanup(self) {
        self.guard.shutdown().await;
        self.database.cleanup().await;
    }
}
async fn call(
    app: &Router,
    cookies: &str,
    path: &str,
    fields: Option<&[(&str, &str)]>,
) -> (StatusCode, Value, axum::http::HeaderMap) {
    let mut req = if fields.is_some() {
        Request::post(path)
    } else {
        Request::get(path)
    }
    .header("accept", "application/json")
    .header("cookie", cookies);
    let body = if let Some(fields) = fields {
        req = req.header("content-type", "application/x-www-form-urlencoded");
        url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(fields.iter().copied())
            .finish()
    } else {
        String::new()
    };
    let response = app
        .clone()
        .oneshot(req.body(Body::from(body)).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let value = if body.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&body)
            .unwrap_or_else(|_| panic!("{path}: {}", String::from_utf8_lossy(&body)))
    };
    (status, value, headers)
}

#[tokio::test]
#[ignore = "requires dedicated PostgreSQL and Redis"]
async fn approval_progress_members_and_audit_share_existing_security() {
    let f = Fixture::new().await;
    let (admin, csrf) = f.admin_login().await;
    let (owner, owner_csrf, _, _) = f.login(f.user).await;
    let router = user_center::router::build(f.state.clone());
    f.sql("INSERT INTO enrollments(id,app_id,email,token_hash,status,expires_at,created_at) SELECT uuidv7(),$1,'other@example.test',n::text,'pending_approval',now()+interval '1 day',now()-n*interval '1 minute' FROM generate_series(1,105) n",vec![f.app.into()]).await;
    let rejected_token = pero_utils::crypto::generate_token();
    f.sql("INSERT INTO enrollments(id,email,token_hash,status,reason,expires_at) VALUES($1,'new@example.test',$2,'rejected','Needs review',now()+interval '1 day')",vec![Uuid::now_v7().into(),pero_utils::crypto::sha256_hex(&rejected_token).into()]).await;
    let rejected =
        user_center::service::enrollment::progress_by_token(&f.state.db, &rejected_token)
            .await
            .unwrap();
    assert_eq!(rejected.reason, "Needs review");
    assert!(
        user_center::service::enrollment::lookup(&f.state.db, &rejected_token)
            .await
            .is_err()
    );
    let own = Uuid::now_v7();
    f.sql("INSERT INTO enrollments(id,app_id,email,token_hash,status,expires_at) VALUES($1,$2,'member@example.test','owner-token','ready',now()+interval '1 day')",vec![own.into(),f.app.into()]).await;
    let (_, page, _) = call(
        &router,
        &admin,
        "/dashboard/registration?status=pending_approval&page=3",
        None,
    )
    .await;
    assert_eq!(page["data"]["pending_count"], 105);
    assert!(!page["data"]["rows"].as_array().unwrap().is_empty());
    assert!(!page.to_string().contains("token_hash"));
    let (_, progress, _) = call(&router, &owner, "/account/applications", None).await;
    assert_eq!(
        progress["data"]["progress"]["rows"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        progress["data"]["progress"]["rows"][0]["id"],
        own.to_string()
    );
    let (_, resumed, headers) = call(
        &router,
        &owner,
        &format!("/account/enrollments/{own}"),
        Some(&[("csrf_token", &owner_csrf), ("action", "continue")]),
    )
    .await;
    assert_eq!(resumed["redirect"], "/sso/register");
    assert!(
        headers
            .get_all("set-cookie")
            .iter()
            .any(|v| v.to_str().unwrap().starts_with("pero_enrollment="))
    );
    let foreign = Uuid::now_v7();
    assert_ne!(
        call(
            &router,
            &owner,
            &format!("/account/enrollments/{foreign}"),
            Some(&[("csrf_token", &owner_csrf), ("action", "withdraw")])
        )
        .await
        .0,
        StatusCode::OK
    );
    let members = format!("/dashboard/apps/{}/members", f.app);
    assert_eq!(
        call(
            &router,
            &admin,
            &members,
            Some(&[
                ("csrf_token", &csrf),
                ("action", "grant"),
                ("username", "workflow_user")
            ])
        )
        .await
        .1["code"],
        0
    );
    let (_, list, _) = call(
        &router,
        &admin,
        &format!("{members}?q=workflow&status=active"),
        None,
    )
    .await;
    assert_eq!(list["data"]["rows"][0]["user_id"], f.user.to_string());
    assert_eq!(
        call(
            &router,
            &admin,
            &members,
            Some(&[
                ("csrf_token", &csrf),
                ("action", "revoke"),
                ("user_id", &f.user.to_string())
            ])
        )
        .await
        .1["code"],
        0
    );
    let (_, list, _) = call(&router, &admin, &format!("{members}?status=disabled"), None).await;
    assert_eq!(list["data"]["rows"].as_array().unwrap().len(), 1);
    call(
        &router,
        &admin,
        &format!("/dashboard/apps/{}/edit", f.app),
        Some(&[
            ("csrf_token", &csrf),
            ("name", "After"),
            ("code", "workflow-app"),
            ("app_type", "web"),
            ("description", ""),
            ("homepage_url", ""),
            ("logo_url", ""),
        ]),
    )
    .await;
    let (_, events, _) = call(
        &router,
        &admin,
        &format!(
            "/dashboard/audit?q=workflow_admin&target={}&outcome=success",
            f.app
        ),
        None,
    )
    .await;
    let id = events["data"]["rows"][0]["id"].as_str().unwrap();
    let (_, detail, _) = call(&router, &admin, &format!("/dashboard/audit/{id}"), None).await;
    assert_eq!(
        detail["data"]["event"]["details"]["name"],
        json!({"before":"Before","after":"After"})
    );
    assert!(!detail.to_string().contains("secret_hash"));
    // Full sign-in alerts are enqueued in the same transaction, without credentials.
    let count = f
        .state
        .db
        .query_one_raw(Statement::from_string(
            DbBackend::Postgres,
            "SELECT count(*) AS n FROM notification_outbox WHERE kind='new_login'".to_owned(),
        ))
        .await
        .unwrap()
        .unwrap()
        .try_get::<i64>("", "n")
        .unwrap();
    assert!(count >= 1);
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires dedicated PostgreSQL and Redis"]
async fn rotation_and_revocation_are_visible_to_online_clients() {
    let f = Fixture::new().await;
    user_center::service::access::grant_app(&f.state.db, f.user, f.app)
        .await
        .unwrap();
    let (_, _, sid, raw) = f.login(f.user).await;
    let at = f.token(sid);
    let router = user_center::router::build(f.state.clone());
    let rotated = user_center::service::client::rotate_secret(&f.state.db, f.client, 3600)
        .await
        .unwrap();
    for secret in [&f.secret, &rotated] {
        let (status, v, _) = call(
            &router,
            "",
            "/api/oauth2/introspect",
            Some(&[
                ("client_id", &f.client.to_string()),
                ("client_secret", secret),
                ("token", &at),
            ]),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(v["active"], true);
    }
    user_center::service::client::retire_secret(&f.state.db, f.client)
        .await
        .unwrap();
    assert_eq!(
        call(
            &router,
            "",
            "/api/oauth2/introspect",
            Some(&[
                ("client_id", &f.client.to_string()),
                ("client_secret", &f.secret),
                ("token", &at)
            ])
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        call(
            &router,
            "",
            "/api/oauth2/revoke",
            Some(&[
                ("client_id", &f.client.to_string()),
                ("client_secret", &rotated),
                ("token", &at)
            ])
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        call(
            &router,
            "",
            "/api/oauth2/introspect",
            Some(&[
                ("client_id", &f.client.to_string()),
                ("client_secret", &rotated),
                ("token", &at)
            ])
        )
        .await
        .1,
        json!({"active":false})
    );
    assert!(
        f.state
            .session_service()
            .validate(&raw)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        user_center::service::access::active_app_access(&f.state.db, f.user, f.app)
            .await
            .unwrap()
            .is_some()
    );
    assert_eq!(
        call(
            &router,
            "",
            "/api/oauth2/revoke",
            Some(&[
                ("client_id", &f.client.to_string()),
                ("client_secret", &rotated),
                ("token", "unknown-token")
            ])
        )
        .await
        .0,
        StatusCode::OK
    );
    let client = user_center::db::entity::oauth_clients::Entity::find_by_id(f.client)
        .one(&f.state.db)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(client.token_version, 0);
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires dedicated PostgreSQL and Redis"]
async fn account_selection_preserves_authorization_and_switches_the_session() {
    let f = Fixture::new().await;
    user_center::service::access::grant_app(&f.state.db, f.user, f.app)
        .await
        .unwrap();
    let (cookies, csrf, _, raw) = f.login(f.user).await;
    f.sql(
        "INSERT INTO user_consents(user_id,client_id,scopes) VALUES($1,$2,ARRAY['openid'])",
        vec![f.user.into(), f.client.into()],
    )
    .await;
    let router = user_center::router::build(f.state.clone());
    let pkce = pero_utils::oauth::pkce::PkcePair::generate();
    let uri = format!(
        "/oauth2/authorize?client_id={}&redirect_uri=https%3A%2F%2Fclient.example.test%2Fcallback&response_type=code&scope=openid&prompt=select_account&state=preserved&code_challenge={}&code_challenge_method=S256",
        f.client, pkce.code_challenge
    );
    for action in ["current", "other"] {
        let (_, redirect, _) = call(&router, &cookies, &uri, None).await;
        let url = redirect["redirect"].as_str().unwrap();
        let (_, selection, _) = call(&router, &cookies, url, None).await;
        assert_eq!(selection["view"], "SelectAccountView");
        let token = selection["data"]["token"].as_str().unwrap();
        let (_, next, _) = call(
            &router,
            &cookies,
            "/sso/select-account",
            Some(&[("csrf_token", &csrf), ("token", token), ("action", action)]),
        )
        .await;
        if action == "current" {
            let target = next["redirect"].as_str().unwrap();
            assert!(target.contains("code=") && target.contains("state=preserved"));
        } else {
            assert_eq!(next["redirect"], "/sso/login");
            assert!(
                f.state
                    .session_service()
                    .validate(&raw)
                    .await
                    .unwrap()
                    .is_none()
            );
        }
    }
    // An incomplete MFA/recovery session is still a browser credential and
    // must be revoked when the user chooses another account.
    for recovery in [false, true] {
        let (cookies, csrf, sid, _) = f.login(f.user).await;
        f.sql(
            "UPDATE sso_sessions SET mfa_required=true,recovery_pending=$2 WHERE id=$1",
            vec![sid.into(), recovery.into()],
        )
        .await;
        let (_, next, headers) = call(
            &router,
            &cookies,
            "/sso/select-account",
            Some(&[("csrf_token", &csrf), ("action", "other")]),
        )
        .await;
        assert!(
            next["redirect"]
                .as_str()
                .unwrap()
                .starts_with("/account/login")
        );
        assert!(headers.get_all("set-cookie").iter().any(|v| {
            let value = v.to_str().unwrap();
            value.starts_with("pero_sso=") && value.contains("Max-Age=0")
        }));
        let session = user_center::db::entity::sso_sessions::Entity::find_by_id(sid)
            .one(&f.state.db)
            .await
            .unwrap()
            .unwrap();
        assert!(session.revoked_at.is_some());
        assert_eq!(session.revoke_reason.as_deref(), Some("account_switch"));
    }
    f.cleanup().await;
}
