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

// Keep integration workloads below the credential worker limit.
static TEST_JOBS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(3);

#[tokio::test]
#[ignore = "requires dedicated PostgreSQL and Redis"]
async fn contact_mutations_revalidate_the_authenticated_session() {
    use user_center::service::contact::{ContactChannel, ContactError, ContactVerificationService};

    let f = Fixture::new().await;
    let (_, _, _, raw) = f.login(f.user).await;
    let session = f
        .state
        .session_service()
        .validate(&raw)
        .await
        .unwrap()
        .unwrap();
    let contacts = ContactVerificationService::new(&f.state);
    let (code, nonce) = contacts
        .create_contact_request(
            &session,
            ContactChannel::Email,
            "verified-new@example.test".into(),
            None,
        )
        .await
        .ok()
        .unwrap();
    // Model a request that passed HTTP authentication before another request revoked it.
    f.state
        .session_service()
        .revoke_login_state(session.id, "user_revoked")
        .await
        .unwrap();
    assert!(matches!(
        contacts.verify_contact(&session, &nonce, &code).await,
        Err(ContactError::Unauthorized)
    ));
    assert!(matches!(
        contacts.cancel_contact(&session, &nonce).await,
        Err(ContactError::Unauthorized)
    ));
    assert!(matches!(
        contacts
            .create_contact_request(
                &session,
                ContactChannel::Phone,
                "+15557654321".into(),
                Some("https://issuer.example.test"),
            )
            .await,
        Err(ContactError::Unauthorized)
    ));
    let row = f.state.db.query_one_raw(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "SELECT email::text,(SELECT count(*) FROM contact_change_requests WHERE user_id=$1) AS requests,(SELECT count(*) FROM notification_outbox WHERE kind='verify_contact') AS queued FROM users WHERE id=$1",
        [f.user.into()],
    )).await.unwrap().unwrap();
    assert_eq!(
        row.try_get::<String>("", "email").unwrap(),
        "member@example.test"
    );
    assert_eq!(row.try_get::<i64>("", "requests").unwrap(), 1);
    assert_eq!(row.try_get::<i64>("", "queued").unwrap(), 0);
    let (_, _, _, raw) = f.login(f.user).await;
    let fresh = f
        .state
        .session_service()
        .validate(&raw)
        .await
        .unwrap()
        .unwrap();
    assert!(contacts.verify_contact(&fresh, &nonce, &code).await.is_ok());
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires dedicated PostgreSQL and Redis"]
async fn delegated_user_invitations_follow_current_permissions() {
    use user_center::service::enrollment;

    let f = Fixture::new().await;
    let actor = database::management_actor(&f.state.db).await;
    f.sql(
        "UPDATE admin_roles SET role='admin' WHERE user_id=$1",
        vec![actor.session.user_id.into()],
    )
    .await;
    f.sql(
        "INSERT INTO admin_permission_state(user_id) VALUES($1)",
        vec![actor.session.user_id.into()],
    )
    .await;
    f.sql("INSERT INTO admin_permissions(user_id,permission) VALUES($1,'users.read'),($1,'users.create')", vec![actor.session.user_id.into()]).await;

    // UsersCreate permits platform invitations, never app grants or domain exceptions.
    let address = format!("delegated-{}@example.test", Uuid::now_v7().simple());
    assert!(
        enrollment::start(
            &f.state,
            &address,
            Some(f.app),
            Some((&actor.session, false, ""))
        )
        .await
        .is_err()
    );
    assert!(
        enrollment::start(
            &f.state,
            &address,
            None,
            Some((&actor.session, true, "exception"))
        )
        .await
        .is_err()
    );
    for complete in [true, false] {
        let address = format!("delegated-{}@example.test", Uuid::now_v7().simple());
        enrollment::start(&f.state, &address, None, Some((&actor.session, false, "")))
            .await
            .unwrap();
        let row = f.state.db.query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT pgp_sym_decrypt(n.payload_enc,current_setting('app.encrypt_key')) AS payload FROM notification_outbox n JOIN enrollments e ON e.id=n.enrollment_id WHERE e.email=$1",
            [address.clone().into()],
        )).await.unwrap().unwrap();
        let payload: Value =
            serde_json::from_str(&row.try_get::<String>("", "payload").unwrap()).unwrap();
        let token = url::Url::parse(payload["link"].as_str().unwrap())
            .unwrap()
            .query_pairs()
            .find(|(key, _)| key == "token")
            .unwrap()
            .1
            .into_owned();
        enrollment::verify(&f.state, &token).await.unwrap();
        if complete {
            enrollment::finalize(
                &f.state,
                &token,
                "delegated_invitee",
                "ValidPass123!",
                None,
                None,
            )
            .await
            .unwrap();
        } else {
            f.sql(
                "DELETE FROM admin_permissions WHERE user_id=$1 AND permission='users.create'",
                vec![actor.session.user_id.into()],
            )
            .await;
            assert!(
                enrollment::finalize(
                    &f.state,
                    &token,
                    "revoked_invitee",
                    "ValidPass123!",
                    None,
                    None
                )
                .await
                .is_err()
            );
        }
    }
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires dedicated PostgreSQL and Redis"]
async fn administrator_authorization_does_not_block_own_token_issuance() {
    use sea_orm::TransactionTrait;
    use user_center::service::{access::lock_grant_access, permissions};

    let f = Fixture::new().await;
    let actor = database::management_actor(&f.state.db).await;
    f.sql(
        "INSERT INTO user_app_access(user_id,app_id) VALUES($1,$2)",
        vec![actor.session.user_id.into(), f.app.into()],
    )
    .await;
    let management = f.state.db.begin().await.unwrap();
    permissions::authorize(&management, &actor).await.unwrap();
    let issuance = f.state.db.begin().await.unwrap();
    // Issuance takes app/access locks before reading the user. An exclusive
    // actor lock would block it here while a management mutation waits for app/access.
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        lock_grant_access(&issuance, actor.session.user_id, f.app),
    )
    .await;
    management.rollback().await.unwrap();
    issuance.rollback().await.unwrap();
    f.cleanup().await;
    assert!(
        result
            .expect("actor authorization blocked token issuance")
            .unwrap()
            .is_some()
    );
}

struct Fixture {
    _permit: tokio::sync::SemaphorePermit<'static>,
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
        let permit = TEST_JOBS.acquire().await.unwrap();
        let database = database::DatabaseFixture::new().await;
        let config:AppConfig=serde_json::from_value(json!({
            "database":{"url":database.url,"encrypt_key":"workflow-test-key","min_connections":1,"max_connections":8},
            "redis":{"url":std::env::var("PERO_TEST_REDIS_URL").unwrap()},
            "sso":{"cookie_signing_secret":"workflow-test-signing-key-long-enough","cookie_secure":false},
            "oidc":{"issuer":"https://issuer.example.test"},
            "notification":{"endpoint":"https://notifications.example.test","bearer_token":"test-gateway-secret"},
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
            _permit: permit,
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
    user_center::service::access::grant_app(
        &f.state.db,
        &database::management_actor(&f.state.db).await,
        f.user,
        f.app,
    )
    .await
    .unwrap();
    let (_, _, sid, raw) = f.login(f.user).await;
    let at = f.token(sid);
    let router = user_center::router::build(f.state.clone());
    let rotated = user_center::service::client::rotate_secret(
        &f.state.db,
        &database::management_actor(&f.state.db).await,
        f.client,
        3600,
    )
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
    user_center::service::client::retire_secret(
        &f.state.db,
        &database::management_actor(&f.state.db).await,
        f.client,
    )
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
    user_center::service::access::grant_app(
        &f.state.db,
        &database::management_actor(&f.state.db).await,
        f.user,
        f.app,
    )
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

#[tokio::test]
#[ignore = "requires dedicated PostgreSQL and Redis"]
async fn assisted_recovery_and_admin_session_interventions() {
    use user_center::service::{
        account::AccountService, login::LoginService, password::PasswordIdentityService, security,
    };
    let f = Fixture::new().await;
    let (admin_cookies, csrf) = f.admin_login().await;
    let router = user_center::router::build(f.state.clone());
    // A verified social-only account can establish a local recovery credential.
    user_center::service::recovery::request(&f.state, "member@example.test")
        .await
        .unwrap();
    let row = f.state.db.query_one_raw(Statement::from_sql_and_values(DbBackend::Postgres,
        "SELECT pgp_sym_decrypt(payload_enc,current_setting('app.encrypt_key')) AS payload FROM notification_outbox WHERE user_id=$1 AND kind='reset_password'",[f.user.into()])).await.unwrap().unwrap();
    let payload: Value =
        serde_json::from_str(&row.try_get::<String>("", "payload").unwrap()).unwrap();
    let link = url::Url::parse(payload["link"].as_str().unwrap()).unwrap();
    let token = link
        .query_pairs()
        .find(|(k, _)| k == "token")
        .unwrap()
        .1
        .into_owned();
    let account = AccountService::new(&f.state);
    assert!(
        account
            .reset_password(&token, "RecoveryPassword123", "RecoveryPassword123")
            .await
            .is_ok()
    );
    assert!(
        PasswordIdentityService::find(&f.state.db, f.user)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        account
            .reset_password(&token, "OtherPassword123", "OtherPassword123")
            .await
            .is_err()
    );
    let (user_cookies, _, sid, raw) = f.login(f.user).await;
    f.sql("INSERT INTO user_mfa(user_id,secret_enc,enabled,recovery_hashes) VALUES($1,pgp_sym_encrypt('GEZDGNBVGY3TQOJQ',current_setting('app.encrypt_key')),true,ARRAY['old-code-hash'])",vec![f.user.into()]).await;
    let path = format!("/dashboard/users/{}/security", f.user);
    let login = LoginService::new(&f.state.db, &f.state.cache);
    for _ in 0..5 {
        login.incr_failure(f.user).await;
    }
    let (_, view, _) = call(&router, &admin_cookies, &path, None).await;
    assert_eq!(view["data"]["login_lock"]["locked"], true);
    assert!(
        view["data"]["login_lock"]["retry_after_seconds"]
            .as_i64()
            .unwrap()
            > 0
    );
    let (status, _, _) = call(&router, &user_cookies, &path, None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _, _) = call(
        &router,
        &admin_cookies,
        &path,
        Some(&[
            ("csrf_token", "invalid"),
            ("action", "unlock"),
            ("reason", "test"),
        ]),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(login.is_account_locked(f.user).await.ok().unwrap());
    let (status, _, _) = call(
        &router,
        &admin_cookies,
        &path,
        Some(&[
            ("csrf_token", &csrf),
            ("action", "unlock"),
            ("reason", "verified owner"),
        ]),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(!login.is_account_locked(f.user).await.ok().unwrap());
    // A session identifier from another account must not be revoked.
    let (_, _, alien, _) = f.login(f.admin).await;
    let (status, _, _) = call(
        &router,
        &admin_cookies,
        &path,
        Some(&[
            ("csrf_token", &csrf),
            ("action", "revoke_one"),
            ("session_id", &alien.to_string()),
            ("reason", "test"),
        ]),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(
        f.state
            .session_service()
            .validate(&raw)
            .await
            .unwrap()
            .is_some()
    );
    let (status, _, _) = call(
        &router,
        &admin_cookies,
        &path,
        Some(&[
            ("csrf_token", &csrf),
            ("action", "revoke_one"),
            ("session_id", &sid.to_string()),
            ("reason", "suspicious device"),
        ]),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        f.state
            .session_service()
            .validate(&raw)
            .await
            .unwrap()
            .is_none()
    );
    let (_, _, _, raw) = f.login(f.user).await;
    let (status, result, _) = call(
        &router,
        &admin_cookies,
        &path,
        Some(&[
            ("csrf_token", &csrf),
            ("action", "recover_mfa"),
            ("reason", "ticket 123; identity verified"),
        ]),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{result}");
    let code = result["data"]["secret"].as_str().unwrap();
    assert_eq!(result["data"]["purpose"], "mfa_recovery");
    assert!(
        f.state
            .session_service()
            .validate(&raw)
            .await
            .unwrap()
            .is_none()
    );
    let factor = security::factor(&f.state.db, f.user)
        .await
        .unwrap()
        .unwrap();
    assert!(factor.enabled);
    assert!(factor.recovery_hashes.is_empty());
    assert_eq!(
        factor.assisted_recovery_hash.as_deref(),
        Some(pero_utils::crypto::sha256_hex(code).as_str())
    );
    let (_, _, pending, _) = f.login(f.user).await;
    let session = user_center::db::entity::sso_sessions::Entity::find_by_id(pending)
        .one(&f.state.db)
        .await
        .unwrap()
        .unwrap();
    f.sql("UPDATE user_mfa SET assisted_recovery_expires_at=now()-interval '1 second' WHERE user_id=$1",vec![f.user.into()]).await;
    assert!(
        user_center::service::mfa::change(&f.state, &session, "recover", code, "")
            .await
            .is_err()
    );
    f.sql("UPDATE user_mfa SET assisted_recovery_expires_at=now()+interval '15 minutes' WHERE user_id=$1",vec![f.user.into()]).await;
    let change = user_center::service::mfa::change(&f.state, &session, "recover", code, "")
        .await
        .unwrap();
    assert!(
        f.state
            .session_service()
            .validate(change.token.as_ref().unwrap())
            .await
            .unwrap()
            .is_none()
    );
    let current = user_center::db::entity::sso_sessions::Entity::find_by_id(change.session_id)
        .one(&f.state.db)
        .await
        .unwrap()
        .unwrap();
    assert!(current.recovery_pending);
    assert!(
        user_center::service::mfa::change(&f.state, &current, "recover", code, "")
            .await
            .is_err()
    );
    user_center::service::mfa::change(&f.state, &current, "setup", "", "")
        .await
        .unwrap();
    let draft = security::factor(&f.state.db, f.user)
        .await
        .unwrap()
        .unwrap();
    let otp = security::totp(draft.pending_secret.as_deref().unwrap(), "workflow_user")
        .unwrap()
        .generate_current()
        .to_string();
    let enabled = user_center::service::mfa::change(&f.state, &current, "enable", &otp, "")
        .await
        .unwrap();
    assert_eq!(enabled.codes.unwrap().len(), 8);
    assert!(
        f.state
            .session_service()
            .validate(enabled.token.as_ref().unwrap())
            .await
            .unwrap()
            .is_some()
    );
    let audit = f.state.db.query_one_raw(Statement::from_sql_and_values(DbBackend::Postgres,
        "SELECT details::text AS details FROM audit_events WHERE action='admin_mfa_recovery' AND target=$1",[f.user.to_string().into()])).await.unwrap().unwrap();
    let details = audit.try_get::<String>("", "details").unwrap();
    assert!(details.contains("ticket 123"));
    assert!(!details.contains(code));
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires dedicated PostgreSQL and Redis"]
async fn guided_integration_completes_authorization_and_validates_tokens() {
    let f = Fixture::new().await;
    let (cookies, csrf) = f.admin_login().await;
    user_center::service::access::grant_app(
        &f.state.db,
        &database::management_actor(&f.state.db).await,
        f.admin,
        f.app,
    )
    .await
    .unwrap();
    let key = user_center::db::helper::signing_key::find_active_signing_key(&f.state.db)
        .await
        .unwrap()
        .unwrap();
    user_center::db::crypto_expr::update_signing_key_private_key(
        &f.state.db,
        include_str!("../../../tests/fixtures/rsa-private.pem"),
        key.key.id,
    )
    .await
    .unwrap();
    let callback = "https://issuer.example.test/oauth2/diagnostic/callback";
    f.sql("UPDATE oauth_clients SET redirect_uris=array_append(redirect_uris,$2),require_pkce=true WHERE id=$1",vec![f.client.into(),callback.into()]).await;
    let router = user_center::router::build(f.state.clone());
    f.sql(
        "UPDATE oauth_clients SET scopes=ARRAY['openid','profile'] WHERE id=$1",
        vec![f.client.into()],
    )
    .await;
    f.sql("INSERT INTO user_consents(user_id,client_id,scopes) VALUES($1,$2,ARRAY['openid','profile'])",vec![f.admin.into(),f.client.into()]).await;
    let path = format!("/dashboard/apps/{}/integration", f.app);
    let (status, view, _) = call(&router, &cookies, &path, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(view["view"], "IntegrationView");
    assert!(
        view["data"]["checks"]
            .as_array()
            .unwrap()
            .iter()
            .all(|c| c["passed"] == true)
    );
    // Cancellation must leave existing business consent untouched as well.
    let session = f
        .state
        .session_service()
        .validate(
            cookies
                .split("pero_sso=")
                .nth(1)
                .unwrap()
                .split(';')
                .next()
                .unwrap(),
        )
        .await
        .unwrap()
        .unwrap();
    let url = user_center::service::integration::start(&f.state, &session, f.app, f.client)
        .await
        .unwrap();
    let request_id = url::Url::parse(&url)
        .unwrap()
        .query_pairs()
        .find(|(key, _)| key == "request")
        .unwrap()
        .1
        .into_owned();
    let request = user_center::service::integration::authorization_request(
        &f.state,
        &session,
        Uuid::parse_str(&request_id).unwrap(),
    )
    .await
    .unwrap();
    f.state
        .oauth_service()
        .deny_authorization_request(request.id, &session)
        .await
        .unwrap();
    let saved = f
        .state
        .db
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT scopes FROM user_consents WHERE user_id=$1 AND client_id=$2",
            [f.admin.into(), f.client.into()],
        ))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        saved.try_get::<Vec<String>>("", "scopes").unwrap(),
        vec!["openid", "profile"]
    );
    for public in [false, true] {
        if public {
            f.sql(
                "UPDATE oauth_clients SET type='public',secret_hash=NULL WHERE id=$1",
                vec![f.client.into()],
            )
            .await;
        }
        let (_, start, _) = call(
            &router,
            &cookies,
            &path,
            Some(&[
                ("csrf_token", &csrf),
                ("action", "start"),
                ("client_id", &f.client.to_string()),
            ]),
        )
        .await;
        let authorize = url::Url::parse(start["redirect"].as_str().unwrap()).unwrap();
        let authorize_path = format!("{}?{}", authorize.path(), authorize.query().unwrap());
        let (other_cookies, _, _, _) = f.login(f.user).await;
        let (_, rejected, _) = call(&router, &other_cookies, &authorize_path, None).await;
        assert_eq!(rejected["redirect"], "/dashboard/apps");
        let (_, _, headers) = call(&router, &cookies, &authorize_path, None).await;
        let extra = headers
            .get_all("set-cookie")
            .iter()
            .map(|v| v.to_str().unwrap().split(';').next().unwrap())
            .collect::<Vec<_>>()
            .join("; ");
        let consent_cookies = format!("{cookies}; {extra}");
        let (_, consent, _) = call(&router, &consent_cookies, "/sso/consent", None).await;
        let (_, accepted, _) = call(
            &router,
            &consent_cookies,
            "/sso/consent",
            Some(&[
                ("csrf_token", &csrf),
                ("action", "allow"),
                (
                    "request_token",
                    consent["data"]["request_token"].as_str().unwrap(),
                ),
            ]),
        )
        .await;
        let consent_row = f
            .state
            .db
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "SELECT scopes FROM user_consents WHERE user_id=$1 AND client_id=$2",
                [f.admin.into(), f.client.into()],
            ))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            consent_row.try_get::<Vec<String>>("", "scopes").unwrap(),
            vec!["openid", "profile"]
        );
        let target = url::Url::parse(accepted["redirect"].as_str().unwrap()).unwrap();
        let callback_path = format!("{}?{}", target.path(), target.query().unwrap());
        // A different session cannot consume this callback's state.
        let (other, _, other_sid, _) = f.login(f.admin).await;
        f.sql(
            "UPDATE sso_sessions SET mfa_verified_at=now() WHERE id=$1",
            vec![other_sid.into()],
        )
        .await;
        let (status, expired, _) = call(&router, &other, &callback_path, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(expired["redirect"], "/dashboard/apps");
        let (status, callback_result, _) = call(&router, &cookies, &callback_path, None).await;
        assert_eq!(status, StatusCode::OK);
        let result_path = callback_result["redirect"].as_str().unwrap();
        assert!(!result_path.contains("code="));
        let (_, ready, _) = call(&router, &cookies, result_path, None).await;
        let ticket = ready["data"]["test"].as_str().unwrap();
        assert_eq!(ready["data"]["test_ready"], true);
        if !public {
            let (status, _, _) = call(
                &router,
                &cookies,
                &path,
                Some(&[
                    ("csrf_token", &csrf),
                    ("action", "finish"),
                    ("client_id", &f.client.to_string()),
                    ("test", ticket),
                    ("client_secret", "wrong"),
                ]),
            )
            .await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
        }
        let mut form = vec![
            ("csrf_token", csrf.as_str()),
            ("action", "finish"),
            ("test", ticket),
        ];
        let client_id = f.client.to_string();
        form.push(("client_id", &client_id));
        if !public {
            form.push(("client_secret", &f.secret));
        }
        let (status, done, _) = call(&router, &cookies, &path, Some(&form)).await;
        assert_eq!(status, StatusCode::OK, "{done}");
        assert_eq!(done["data"]["test_success"], true);
        assert!(done["data"].get("access_token").is_none());
        let (status, expired, _) = call(&router, &cookies, result_path, None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(expired["view"], "IntegrationView");
        assert_eq!(expired["data"]["test"], "");
        assert_eq!(expired["data"]["error"], "integration_test_expired");
    }
    let rows = f
        .state
        .db
        .query_all_raw(Statement::from_string(
            DbBackend::Postgres,
            "SELECT revoked_at FROM refresh_tokens".to_string(),
        ))
        .await
        .unwrap();
    assert!(!rows.is_empty());
    assert!(rows.iter().all(|r| {
        r.try_get::<Option<time::OffsetDateTime>>("", "revoked_at")
            .unwrap()
            .is_some()
    }));
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires dedicated PostgreSQL and Redis"]
async fn unlock_audit_failures_and_social_password_recovery() {
    use user_center::service::{
        account::AccountService, login::LoginService, password::PasswordIdentityService,
    };
    let f = Fixture::new().await;
    let mut sms_only = f.state.clone();
    let config = std::sync::Arc::make_mut(&mut sms_only.config);
    config.notification.endpoint.clear();
    config.notification.sms = Some(user_center::config::SmsConfig {
        account_sid: format!("AC{}", "0".repeat(32)),
        auth_token: "test-token".into(),
        from: "+12025550100".into(),
    });
    for contact in ["member@example.test", "missing@example.test"] {
        user_center::service::recovery::request(&sms_only, contact)
            .await
            .expect("disabled email delivery must not reveal account existence");
    }
    // An unverified contact cannot request a first password.
    f.sql(
        "UPDATE users SET email_verified_at=NULL WHERE id=$1",
        vec![f.user.into()],
    )
    .await;
    user_center::service::recovery::request(&f.state, "member@example.test")
        .await
        .unwrap();
    let count = f
        .state
        .db
        .query_one_raw(Statement::from_string(
            DbBackend::Postgres,
            "SELECT count(*) AS count FROM password_reset_tokens".to_owned(),
        ))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(count.try_get::<i64>("", "count").unwrap(), 0);
    f.sql(
        "UPDATE users SET email_verified_at=now() WHERE id=$1",
        vec![f.user.into()],
    )
    .await;
    let phone_user = Uuid::now_v7();
    f.sql(
        "INSERT INTO users(id,username,phone,phone_verified_at) VALUES($1,$2,'+12025550123',now())",
        vec![phone_user.into(), phone_user.to_string().into()],
    )
    .await;
    for (user, contact) in [
        (f.user, "member@example.test"),
        (phone_user, "+12025550123"),
    ] {
        assert!(
            PasswordIdentityService::find(&f.state.db, user)
                .await
                .unwrap()
                .is_none()
        );
        user_center::service::recovery::request(&f.state, contact)
            .await
            .unwrap();
        let row=f.state.db.query_one_raw(Statement::from_sql_and_values(DbBackend::Postgres,"SELECT pgp_sym_decrypt(payload_enc,current_setting('app.encrypt_key')) AS payload FROM notification_outbox WHERE user_id=$1 AND kind='reset_password'",[user.into()])).await.unwrap().unwrap();
        let payload: Value =
            serde_json::from_str(&row.try_get::<String>("", "payload").unwrap()).unwrap();
        let link = url::Url::parse(payload["link"].as_str().unwrap()).unwrap();
        let token = link
            .query_pairs()
            .find(|(key, _)| key == "token")
            .unwrap()
            .1
            .into_owned();
        assert!(
            AccountService::new(&f.state)
                .reset_password(&token, "RecoveryPassword123", "RecoveryPassword123")
                .await
                .is_ok()
        );
        let identity = PasswordIdentityService::find(&f.state.db, user)
            .await
            .unwrap()
            .unwrap();
        assert!(
            PasswordIdentityService::verify_password_hash(
                "RecoveryPassword123",
                identity.password_hash.as_deref()
            )
            .await
            .unwrap()
        );
        assert!(
            !AccountService::new(&f.state)
                .inspect_password_reset_token(&token)
                .await
                .ok()
                .unwrap()
        );
    }
    let (cookies, csrf) = f.admin_login().await;
    let router = user_center::router::build(f.state.clone());
    let login = LoginService::new(&f.state.db, &f.state.cache);
    for _ in 0..5 {
        login.incr_failure(f.user).await;
    }
    f.sql("CREATE FUNCTION reject_unlock_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='admin_sessions:unlock' THEN RAISE EXCEPTION 'injected audit failure'; END IF; RETURN NEW; END $$",vec![]).await;
    f.sql("CREATE TRIGGER reject_unlock_audit BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION reject_unlock_audit()",vec![]).await;
    let path = format!("/dashboard/users/{}/security", f.user);
    let form = [
        ("csrf_token", csrf.as_str()),
        ("action", "unlock"),
        ("reason", "verified incident"),
    ];
    assert_eq!(
        call(&router, &cookies, &path, Some(&form)).await.0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert!(login.is_account_locked(f.user).await.ok().unwrap());
    f.sql("DROP TRIGGER reject_unlock_audit ON audit_events", vec![])
        .await;
    f.sql("CREATE TRIGGER reject_unlock_audit BEFORE UPDATE ON audit_events FOR EACH ROW EXECUTE FUNCTION reject_unlock_audit()",vec![]).await;
    assert_eq!(
        call(&router, &cookies, &path, Some(&form)).await.0,
        StatusCode::OK
    );
    assert!(!login.is_account_locked(f.user).await.ok().unwrap());
    let audit=f.state.db.query_one_raw(Statement::from_sql_and_values(DbBackend::Postgres,"SELECT outcome,details FROM audit_events WHERE action='admin_sessions:unlock' AND target=$1",[f.user.to_string().into()])).await.unwrap().unwrap();
    assert_eq!(audit.try_get::<String>("", "outcome").unwrap(), "pending");
    assert_eq!(
        audit.try_get::<Value>("", "details").unwrap()["reason"]["after"],
        "verified incident"
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires dedicated PostgreSQL and Redis"]
async fn public_oauth_state_is_opaque_and_cannot_mark_diagnostics() {
    use sea_orm::{ColumnTrait, QueryFilter};
    use user_center::db::entity::authorization_requests;
    let f = Fixture::new().await;
    user_center::service::access::grant_app(
        &f.state.db,
        &database::management_actor(&f.state.db).await,
        f.user,
        f.app,
    )
    .await
    .unwrap();
    let (cookies, csrf, sid, _) = f.login(f.user).await;
    let router = user_center::router::build(f.state.clone());
    for state in ["ordinary-state", "pero-diagnostic.client-state"] {
        let mut uri = "/oauth2/authorize".to_string();
        for (key, value) in [
            ("response_type", "code"),
            ("client_id", f.client.to_string().as_str()),
            ("redirect_uri", "https://client.example.test/callback"),
            ("scope", "openid"),
            ("prompt", "consent"),
            ("state", state),
            ("diagnostic_session_id", sid.to_string().as_str()),
        ] {
            pero_utils::encode::append_query_param(&mut uri, key, value);
        }
        let (_, _, headers) = call(&router, &cookies, &uri, None).await;
        let request = authorization_requests::Entity::find()
            .filter(authorization_requests::Column::ClientState.eq(state))
            .one(&f.state.db)
            .await
            .unwrap()
            .unwrap();
        assert!(request.diagnostic_session_id.is_none());
        let extra = headers
            .get_all("set-cookie")
            .iter()
            .map(|v| v.to_str().unwrap().split(';').next().unwrap())
            .collect::<Vec<_>>()
            .join("; ");
        let consent_cookies = format!("{cookies}; {extra}");
        let (_, consent, _) = call(&router, &consent_cookies, "/sso/consent", None).await;
        let (status, result, _) = call(
            &router,
            &consent_cookies,
            "/sso/consent",
            Some(&[
                ("csrf_token", &csrf),
                ("action", "allow"),
                (
                    "request_token",
                    consent["data"]["request_token"].as_str().unwrap(),
                ),
            ]),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{result}");
        let location = url::Url::parse(result["redirect"].as_str().unwrap()).unwrap();
        assert!(
            location
                .query_pairs()
                .any(|(k, v)| k == "code" && !v.is_empty())
        );
        assert!(
            location
                .query_pairs()
                .any(|(k, v)| k == "state" && v == state)
        );
    }
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires dedicated PostgreSQL and Redis"]
async fn dynamic_permissions_are_scoped_versioned_and_revoke_sessions() {
    let f = Fixture::new().await;
    let (super_cookie, super_csrf) = f.admin_login().await;
    f.sql(
        "INSERT INTO admin_roles(user_id,role) VALUES($1,'admin');",
        vec![f.user.into()],
    )
    .await;
    f.sql(
        "INSERT INTO admin_permission_state(user_id) VALUES($1)",
        vec![f.user.into()],
    )
    .await;
    f.sql("INSERT INTO user_mfa(user_id,secret_enc,enabled) VALUES($1,pgp_sym_encrypt('GEZDGNBVGY3TQOJQ',current_setting('app.encrypt_key')),true)",vec![f.user.into()]).await;
    let second = Uuid::now_v7();
    f.sql(
        "INSERT INTO apps(id,code,name) VALUES($1,'permission-hidden','Hidden')",
        vec![second.into()],
    )
    .await;
    let router = user_center::router::build(f.state.clone());
    async fn save(router: &Router, cookies: &str, id: Uuid, body: Value) -> (StatusCode, Value) {
        let response = router
            .clone()
            .oneshot(
                Request::post(format!("/dashboard/admins/{id}/permissions"))
                    .header("cookie", cookies)
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        (status, serde_json::from_slice(&body).unwrap())
    }
    let (cookie, _, sid, _) = f.login(f.user).await;
    f.sql(
        "UPDATE sso_sessions SET mfa_required=true,mfa_verified_at=now() WHERE id=$1",
        vec![sid.into()],
    )
    .await;
    assert_eq!(
        call(&router, &cookie, "/dashboard/apps", None).await.1["data"]["apps"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
    assert_eq!(
        call(&router, &cookie, "/dashboard/admins", None).await.0,
        StatusCode::FORBIDDEN
    );
    let mut input = json!({"csrf_token":super_csrf,"revision":0,"global_permissions":["users.read","users.update"],"app_grants":[{"app_id":f.app,"permissions":["apps.read","clients.read","clients.manage"]}]});
    assert_eq!(
        save(&router, &super_cookie, f.user, input.clone()).await.0,
        StatusCode::OK
    );
    assert!(
        user_center::db::entity::sso_sessions::Entity::find_by_id(sid)
            .one(&f.state.db)
            .await
            .unwrap()
            .unwrap()
            .revoked_at
            .is_some()
    );
    assert_eq!(
        save(&router, &super_cookie, f.user, input.clone()).await.0,
        StatusCode::CONFLICT
    );
    let (cookie, csrf, sid, _) = f.login(f.user).await;
    f.sql(
        "UPDATE sso_sessions SET mfa_required=true,mfa_verified_at=now() WHERE id=$1",
        vec![sid.into()],
    )
    .await;
    let (status, body, _) = call(&router, &cookie, "/dashboard/apps", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["data"]["apps"].as_array().unwrap().len(), 1);
    assert_eq!(
        call(&router, &cookie, &format!("/dashboard/apps/{second}"), None)
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        call(
            &router,
            &cookie,
            &format!("/dashboard/apps/{}/toggle", f.app),
            Some(&[("csrf_token", &csrf)])
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        call(
            &router,
            &cookie,
            &format!("/dashboard/users/{}", f.admin),
            None
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );

    // HEAD uses the same object boundary, and profile access never exposes contact fields.
    let head = router
        .clone()
        .oneshot(
            Request::head(format!("/dashboard/apps/{second}"))
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(head.status(), StatusCode::NOT_FOUND);
    let target = Uuid::now_v7();
    f.sql(
        "INSERT INTO users(id,username,email,phone) VALUES($1,'ordinary_target','private@example.test','+8613800123456')",
        vec![target.into()],
    )
    .await;
    let (_, users, _) = call(&router, &cookie, "/dashboard/users", None).await;
    assert_eq!(users["data"]["users"].as_array().unwrap().len(), 1);
    assert_eq!(users["data"]["users"][0]["email"], "***");
    // Searching must not turn masked contact fields into a substring oracle.
    for search in ["private", "13800123456"] {
        let path = format!("/dashboard/users?q={search}");
        let (_, result, _) = call(&router, &cookie, &path, None).await;
        assert!(result["data"]["users"].as_array().unwrap().is_empty());
        let (_, result, _) = call(&router, &super_cookie, &path, None).await;
        assert_eq!(result["data"]["users"].as_array().unwrap().len(), 1);
    }
    let (_, result, _) = call(&router, &cookie, "/dashboard/users?q=ordinary", None).await;
    assert_eq!(result["data"]["users"].as_array().unwrap().len(), 1);
    let edit = format!("/dashboard/users/{target}/edit");
    assert_eq!(
        call(
            &router,
            &cookie,
            &edit,
            Some(&[("csrf_token", &csrf), ("nickname", "Updated")])
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        call(
            &router,
            &cookie,
            &edit,
            Some(&[("csrf_token", &csrf), ("email", "injected@example.test")])
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    // Administrator edits must enforce the same contact format as self-service edits.
    for (field, invalid) in [("email", "invalid-address"), ("phone", "not-a-phone")] {
        let (status, _, _) = call(
            &router,
            &super_cookie,
            &edit,
            Some(&[("csrf_token", &super_csrf), (field, invalid)]),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
    let unchanged = user_center::db::entity::users::Entity::find_by_id(target)
        .one(&f.state.db)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(unchanged.email.as_deref(), Some("private@example.test"));
    assert_eq!(unchanged.phone.as_deref(), Some("+8613800123456"));
    let client_edit = format!("/dashboard/clients/{}/edit", f.client);
    let mut settings = vec![
        ("csrf_token", csrf.as_str()),
        ("client_type", "confidential"),
        ("name", "Updated"),
        ("redirect_uris", "https://client.example.test/callback"),
        ("post_logout_redirect_uris", ""),
        ("scopes", "openid"),
        ("grant_types", "authorization_code"),
    ];
    assert_eq!(
        call(&router, &cookie, &client_edit, Some(&settings))
            .await
            .0,
        StatusCode::OK
    );
    settings.push(("secret", "injected-secret"));
    assert_eq!(
        call(&router, &cookie, &client_edit, Some(&settings))
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    let audit=f.state.db.query_one_raw(Statement::from_sql_and_values(DbBackend::Postgres,"SELECT details FROM audit_events WHERE target=$1 AND outcome='success' AND details ? 'after_revision'",[format!("/dashboard/admins/{}/permissions",f.user).into()])).await.unwrap().unwrap();
    assert_eq!(
        audit.try_get::<Value>("", "details").unwrap()["after_revision"],
        1
    );
    input["revision"] = json!(1);
    input["app_grants"] = json!([{ "app_id":second,"permissions":["clients.manage"]}]);
    assert_eq!(
        save(&router, &super_cookie, f.user, input.clone()).await.0,
        StatusCode::BAD_REQUEST
    );
    input["app_grants"] = json!([]);
    input["global_permissions"] = json!([]);
    let actor = database::management_actor(&f.state.db).await;
    let replacement = serde_json::from_value(input.clone()).unwrap();
    assert!(
        user_center::service::permissions::replace(
            &f.state.db,
            &actor,
            f.user,
            replacement,
            Uuid::now_v7()
        )
        .await
        .is_err()
    );
    assert!(
        user_center::db::entity::sso_sessions::Entity::find_by_id(sid)
            .one(&f.state.db)
            .await
            .unwrap()
            .unwrap()
            .revoked_at
            .is_none()
    );
    assert_eq!(
        save(&router, &super_cookie, f.user, input).await.0,
        StatusCode::OK
    );
    assert!(
        user_center::db::entity::sso_sessions::Entity::find_by_id(sid)
            .one(&f.state.db)
            .await
            .unwrap()
            .unwrap()
            .revoked_at
            .is_some()
    );
    f.cleanup().await;
}

#[tokio::test]
#[ignore = "requires dedicated PostgreSQL and Redis"]
async fn account_sync_configuration_and_snapshot_require_app_authority() {
    let f = Fixture::new().await;
    let actor = database::management_actor(&f.state.db).await;
    user_center::service::access::grant_app(&f.state.db, &actor, f.user, f.app)
        .await
        .unwrap();
    let (cookies, csrf) = f.admin_login().await;
    let router = user_center::router::build(f.state.clone());
    let path = format!("/dashboard/clients/{}/account-sync", f.client);
    for (endpoint, status) in [
        ("http://127.0.0.1/sync", StatusCode::BAD_REQUEST),
        ("https://rp.example.test/sync", StatusCode::OK),
    ] {
        assert_eq!(
            call(
                &router,
                &cookies,
                &path,
                Some(&[("csrf_token", &csrf), ("account_sync_uri", endpoint)])
            )
            .await
            .0,
            status
        );
    }
    // Delegated client management must not become permission to export global contacts.
    let delegated = database::management_actor(&f.state.db).await;
    f.sql(
        "UPDATE admin_roles SET role='admin' WHERE user_id=$1",
        vec![delegated.session.user_id.into()],
    )
    .await;
    f.sql(
        "INSERT INTO admin_permission_state(user_id) VALUES($1)",
        vec![delegated.session.user_id.into()],
    )
    .await;
    f.sql("INSERT INTO admin_app_permissions(user_id,app_id,permission) VALUES($1,$2,'apps.read'),($1,$2,'clients.read'),($1,$2,'clients.manage')",vec![delegated.session.user_id.into(),f.app.into()]).await;
    let current = user_center::db::entity::oauth_clients::Entity::find_by_id(f.client)
        .one(&f.state.db)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        user_center::service::client::update(
            &f.state.db,
            &delegated,
            f.client,
            user_center::service::client::ClientInput {
                client_type: current.r#type,
                secret: String::new(),
                name: current.name,
                redirect_uris: current.redirect_uris,
                post_logout_redirect_uris: current.post_logout_redirect_uris,
                scopes: vec!["openid".into(), "email".into()],
                grant_types: current.grant_types,
                require_pkce: current.require_pkce,
                access_token_ttl: current.access_token_ttl_seconds,
                refresh_token_ttl: current.refresh_token_ttl_seconds,
                id_token_ttl: current.id_token_ttl_seconds,
            },
        )
        .await,
        Err(user_center::service::ManagementError::Invalid("forbidden"))
    ));
    let fields = [
        ("sub", f.user.to_string()),
        ("client_id", f.client.to_string()),
        ("client_secret", f.secret.clone()),
    ];
    let fields = fields
        .iter()
        .map(|(k, v)| (*k, v.as_str()))
        .collect::<Vec<_>>();
    let (status, snapshot, headers) = call(&router, "", "/api/accounts/sync", Some(&fields)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(snapshot["active"], true);
    assert_eq!(headers["cache-control"], "no-store");
    assert_eq!(snapshot["profile"], json!({}));
    // A valid client cannot query a platform user outside its own app membership.
    assert_eq!(
        call(
            &router,
            "",
            "/api/accounts/sync",
            Some(&[
                ("sub", &f.admin.to_string()),
                ("client_id", &f.client.to_string()),
                ("client_secret", &f.secret)
            ])
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        call(
            &router,
            "",
            "/api/accounts/sync",
            Some(&[
                ("sub", &f.user.to_string()),
                ("client_id", &f.client.to_string()),
                ("client_secret", "wrong")
            ])
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    let (user_cookies, user_csrf, _, _) = f.login(f.user).await;
    assert_eq!(
        call(
            &router,
            &user_cookies,
            &path,
            Some(&[("csrf_token", &user_csrf), ("account_sync_uri", "")])
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    let (_, view, _) = call(&router, &cookies, "/dashboard/notifications", None).await;
    assert_eq!(view["data"]["sync_rows"].as_array().unwrap().len(), 1);
    // Public browser clients have no credentials for server-side provisioning.
    f.sql(
        "UPDATE oauth_clients SET account_sync_uri=NULL,type='public',secret_hash=NULL WHERE id=$1",
        vec![f.client.into()],
    )
    .await;
    assert_eq!(
        call(
            &router,
            &cookies,
            &path,
            Some(&[
                ("csrf_token", &csrf),
                ("account_sync_uri", "https://rp.example.test/sync")
            ])
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        call(
            &router,
            "",
            "/api/accounts/sync",
            Some(&[
                ("sub", &f.user.to_string()),
                ("client_id", &f.client.to_string())
            ])
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    f.cleanup().await;
}
