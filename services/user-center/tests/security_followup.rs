#[path = "support/database.rs"]
mod database;
use axum::{
    Form,
    extract::{Path, State},
    http::Request,
    response::IntoResponse,
};
use axum_extra::extract::cookie::CookieJar;
use sea_orm::{ConnectionTrait, DbBackend, Statement, TransactionTrait};
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
        c["client_version"] = 0.into();
        c["access_version"] = 0.into();
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
#[ignore = "requires dedicated PERO_TEST_DATABASE_URL and PERO_TEST_REDIS_URL"]
async fn authorization_and_recovery_regressions() {
    let fixture = database::DatabaseFixture::new().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let issuer = format!("http://{}", listener.local_addr().unwrap());
    let cfg:user_center::config::AppConfig=serde_json::from_value(serde_json::json!({
 "database":{"url":fixture.url,"encrypt_key":"test-only-key","min_connections":1,"max_connections":8},
 "redis":{"url":std::env::var("PERO_TEST_REDIS_URL").unwrap(),"connect_timeout_secs":1,"command_timeout_secs":1},
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
    // A verification link must survive authentication, including its nonce.
    let verify_path = "/account/profile/verify-contact?nonce=contact-link";
    let response = app
        .clone()
        .oneshot(
            Request::get(verify_path)
                .header("accept", "application/json")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    let redirect: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let login = url::Url::parse(&format!(
        "{issuer}{}",
        redirect["redirect"].as_str().unwrap()
    ))
    .unwrap();
    assert!(
        login
            .query_pairs()
            .any(|(key, value)| key == "redirect" && value == verify_path)
    );

    // Supported-but-disallowed grants differ from grants the server cannot handle.
    sql(&db, "UPDATE oauth_clients SET type='public',grant_types=ARRAY['authorization_code']::citext[] WHERE id=$1", vec![client_b.into()]).await;
    for (grant, expected) in [
        ("refresh_token", "unauthorized_client"),
        ("client_credentials", "unsupported_grant_type"),
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::post("/api/oauth2/token")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(axum::body::Body::from(format!(
                        "client_id=other-client&grant_type={grant}"
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).unwrap()["error"],
            expected
        );
    }
    sql(&db, "UPDATE oauth_clients SET type='confidential',grant_types=ARRAY['authorization_code','refresh_token']::citext[] WHERE id=$1", vec![client_b.into()]).await;
    sql(
        &db,
        "UPDATE oauth_clients SET require_pkce=true WHERE id=$1",
        vec![client_b.into()],
    )
    .await;
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/oauth2/authorize?client_id=other-client&redirect_uri=https%3A%2F%2Fclient.example.test%2Fcallback&response_type=code&scope=openid")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(
        response.headers()["location"]
            .to_str()
            .unwrap()
            .starts_with("https://client.example.test/callback?error=invalid_request")
    );
    // Refuse disallowed grants before creating any authorization state or consent UI.
    sql(
        &db,
        "UPDATE oauth_clients SET grant_types=ARRAY['refresh_token']::citext[] WHERE id=$1",
        vec![client_a.into()],
    )
    .await;
    let before = db
        .query_one_raw(Statement::from_string(
            DbBackend::Postgres,
            "SELECT count(*) AS n FROM authorization_requests",
        ))
        .await
        .unwrap()
        .unwrap()
        .try_get::<i64>("", "n")
        .unwrap();
    let response = app.clone().oneshot(Request::builder()
        .uri("/oauth2/authorize?client_id=admin-client&redirect_uri=https%3A%2F%2Fclient.example.test%2Fcallback&response_type=code&scope=openid&prompt=none&state=grant-check")
        .header("cookie", format!("pero_sso={raw_old}")).body(axum::body::Body::empty()).unwrap()).await.unwrap();
    let location = response.headers()["location"].to_str().unwrap();
    assert!(
        location.contains("error=unauthorized_client") && location.contains("state=grant-check")
    );
    let after = db
        .query_one_raw(Statement::from_string(
            DbBackend::Postgres,
            "SELECT count(*) AS n FROM authorization_requests",
        ))
        .await
        .unwrap()
        .unwrap()
        .try_get::<i64>("", "n")
        .unwrap();
    assert_eq!(before, after);
    sql(&db, "UPDATE oauth_clients SET grant_types=ARRAY['authorization_code','refresh_token']::citext[] WHERE id=$1", vec![client_a.into()]).await;
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
    // Incomplete MFA and recovery are unauthenticated for silent authorization;
    // the protocol must return login_required to the validated client, never UI.
    for recovery in [false, true] {
        sql(&db, "UPDATE sso_sessions SET mfa_required=true,mfa_verified_at=NULL,recovery_pending=$2 WHERE token_hash=$1", vec![pero_utils::crypto::sha256_hex(&raw_old).into(), recovery.into()]).await;
        let response=app.clone().oneshot(Request::builder().uri("/oauth2/authorize?client_id=admin-client&redirect_uri=https%3A%2F%2Fclient.example.test%2Fcallback&response_type=code&scope=openid&prompt=none&state=mfa-silent").header("cookie",format!("pero_sso={raw_old}")).body(axum::body::Body::empty()).unwrap()).await.unwrap();
        let location = response.headers()["location"].to_str().unwrap();
        assert!(
            location.starts_with("https://client.example.test/callback?error=login_required")
                && location.contains("state=mfa-silent"),
            "{location}"
        );
    }
    sql(
        &db,
        "UPDATE sso_sessions SET mfa_required=false,recovery_pending=false WHERE token_hash=$1",
        vec![pero_utils::crypto::sha256_hex(&raw_old).into()],
    )
    .await;
    let selection=app.clone().oneshot(Request::builder().uri("/oauth2/authorize?client_id=admin-client&redirect_uri=https%3A%2F%2Fclient.example.test%2Fcallback&response_type=code&scope=openid&prompt=select_account").header("cookie",format!("pero_sso={raw_old}")).body(axum::body::Body::empty()).unwrap()).await.unwrap();
    assert!(
        selection.headers()["location"]
            .to_str()
            .unwrap()
            .starts_with("/sso/select-account?token=")
    );
    assert!(
        pero_utils::oauth::jwt::verify_id_token(&old_at, &issuer, "admin-client", PUBLIC).is_err()
    );
    // Exhaust one source's shared login-start budget before either endpoint creates state.
    let rate_key = pero_cache_redis::rate_limit_key::rl_login_start_ip
        .key("192.0.2.10/32")
        .unwrap();
    state.cache.set(rate_key.clone(), &60_u64).await.unwrap();
    let count_requests = || async {
        db.query_one_raw(Statement::from_string(
            DbBackend::Postgres,
            "SELECT count(*) AS n FROM authorization_requests".to_owned(),
        ))
        .await
        .unwrap()
        .unwrap()
        .try_get::<i64>("", "n")
        .unwrap()
    };
    let before = count_requests().await;
    for uri in [
        "/oauth2/authorize?client_id=admin-client&redirect_uri=https%3A%2F%2Fclient.example.test%2Fcallback&response_type=code&scope=openid",
        "/sso/social/unknown/login",
    ] {
        let denied = app
            .clone()
            .oneshot(
                Request::get(uri)
                    .extension(axum::extract::ConnectInfo(
                        "192.0.2.10:1234".parse::<std::net::SocketAddr>().unwrap(),
                    ))
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(denied.status(), axum::http::StatusCode::TOO_MANY_REQUESTS);
    }
    assert_eq!(count_requests().await, before);
    state.cache.del(rate_key).await.unwrap();
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
    let form = serde_json::from_value(
        serde_json::json!({"csrf_token":csrf_token,"email":"new@example.test"}),
    )
    .unwrap();
    let actor = database::management_actor(&db).await;
    use sea_orm::EntityTrait;
    let admin = user_center::web::dashboard::guard::AdminContext {
        user: user_center::db::entity::users::Entity::find_by_id(actor.session.user_id)
            .one(&db)
            .await
            .unwrap()
            .unwrap(),
        session: actor.session,
        access: user_center::service::permissions::Access {
            super_admin: true,
            ..Default::default()
        },
    };
    let response = user_center::web::dashboard::users::update(
        State(state.clone()),
        jar,
        admin,
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
            "SELECT count(*) AS n FROM notification_outbox WHERE kind IN ('reset_password','verify_contact')".to_owned(),
        ))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(queued.try_get::<i64>("", "n").unwrap(), 0);
    // Cancellation waiting behind verification must recheck the row state.
    let contact_id = Uuid::now_v7();
    sql(&db, "INSERT INTO contact_change_requests(id,user_id,change_type,new_value,verification_code_hash,nonce,expires_at) VALUES($1,$2,'email','cancel-race@example.test','hash','cancel-race',now()+interval '15 minutes')", vec![contact_id.into(), user.into()]).await;
    let verification = db.begin().await.unwrap();
    let verifier_pid: i32 = verification
        .query_one_raw(Statement::from_string(
            DbBackend::Postgres,
            "SELECT pg_backend_pid() AS pid",
        ))
        .await
        .unwrap()
        .unwrap()
        .try_get("", "pid")
        .unwrap();
    verification
        .execute_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "UPDATE contact_change_requests SET status='verified',verified_at=now() WHERE id=$1",
            [contact_id.into()],
        ))
        .await
        .unwrap();
    let (contact_token, _) = state
        .session_service()
        .create(user, None, None, None, None)
        .await
        .unwrap();
    let contact_session = state
        .session_service()
        .validate(&contact_token)
        .await
        .unwrap()
        .unwrap();
    let cancel_state = state.clone();
    let cancellation = tokio::spawn(async move {
        user_center::service::contact::ContactVerificationService::new(&cancel_state)
            .cancel_contact(&contact_session, "cancel-race")
            .await
            .map_err(|_| ())
    });
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let blocked: bool = db.query_one_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid))) AS blocked",
                [verifier_pid.into()],
            )).await.unwrap().unwrap().try_get("", "blocked").unwrap();
            if blocked { break; }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }).await.unwrap();
    verification.commit().await.unwrap();
    assert!(cancellation.await.unwrap().is_err());
    let row = db
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT status::text AS status FROM contact_change_requests WHERE id=$1",
            [contact_id.into()],
        ))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.try_get::<String>("", "status").unwrap(), "verified");
    // Use a fresh pool for each DDL fault so cached plans cannot bind to public fallback tables.
    for table in [
        "identity_provider_keys",
        "oauth_clients",
        "users",
        "apps",
        "user_app_access",
        "sso_sessions",
        "identity_providers",
        "contact_change_requests",
        "password_reset_tokens",
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
        // Inject faults after startup: startup itself now rejects missing schema/pgcrypto.
        let mut options = sea_orm::ConnectOptions::new(url.as_str());
        options.max_connections(1).sqlx_logging(false);
        let fault_db = sea_orm::Database::connect(options).await.unwrap();
        sql(
            &fault_db,
            "SELECT set_config('app.encrypt_key',$1,false)",
            vec![
                config
                    .database
                    .extras
                    .encrypt_key
                    .expose_secret()
                    .to_owned()
                    .into(),
            ],
        )
        .await;
        let fault_guard = pero_db_seaorm::DatabaseGuard::new(fault_db.clone());
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
        let response = match table {
            "password_reset_tokens" => {
                use user_center::web::sso::{
                    dto::ResetPasswordForm,
                    reset_password::{self, ResetQuery},
                };
                let response = reset_password::get_reset(
                    State(fault_state.clone()),
                    CookieJar::new(),
                    axum::extract::Query(ResetQuery {
                        token: Some(reset.clone()),
                    }),
                )
                .await;
                assert_eq!(
                    response.status(),
                    axum::http::StatusCode::SERVICE_UNAVAILABLE
                );
                let (jar, csrf_token) = fault_state.web_security().ensure_csrf(CookieJar::new());
                reset_password::post_reset(
                    State(fault_state),
                    jar,
                    axum::extract::Query(ResetQuery {
                        token: Some(reset.clone()),
                    }),
                    Form(ResetPasswordForm {
                        csrf_token,
                        new_password: "ResetPassword123!".into(),
                        confirm_password: "ResetPassword123!".into(),
                    }),
                )
                .await
            }
            "identity_providers" => {
                let response = user_center::api::providers::providers(State(fault_state.clone()))
                    .await
                    .into_response();
                assert_eq!(
                    response.status(),
                    axum::http::StatusCode::SERVICE_UNAVAILABLE
                );
                user_center::web::account::login::get(
                    State(fault_state),
                    CookieJar::new(),
                    axum::extract::Query(Default::default()),
                )
                .await
            }
            "contact_change_requests" => {
                let jar = CookieJar::new().add(axum_extra::extract::cookie::Cookie::new(
                    "pero_sso",
                    raw_old.clone(),
                ));
                let (jar, csrf_token) = fault_state.web_security().ensure_csrf(jar);
                let response = user_center::web::account::contact::verify_contact(
                    State(fault_state.clone()),
                    jar,
                    Form(user_center::web::account::contact::VerifyContactNonceForm {
                        csrf_token,
                        nonce: "dependency-probe".into(),
                        code: "123456".into(),
                    }),
                )
                .await;
                assert_eq!(
                    response.status(),
                    axum::http::StatusCode::SERVICE_UNAVAILABLE
                );
                user_center::web::account::profile::get(
                    State(fault_state),
                    CookieJar::new().add(axum_extra::extract::cookie::Cookie::new(
                        "pero_sso",
                        raw_old.clone(),
                    )),
                )
                .await
            }
            _ => {
                user_center::api::userinfo::userinfo(State(fault_state), {
                    let mut headers = axum::http::HeaderMap::new();
                    headers.insert("authorization", format!("Bearer {old_at}").parse().unwrap());
                    headers
                })
                .await
            }
        };
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
    // Password changes preserve credentials on failure and revoke every login on success.
    let (changing, _) = state
        .session_service()
        .create(user, None, None, None, None)
        .await
        .unwrap();
    let session = state
        .session_service()
        .validate(&changing)
        .await
        .unwrap()
        .unwrap();
    let account = user_center::service::account::AccountService::new(&state);
    assert!(matches!(
        account
            .change_password(
                &session,
                Some("wrong-password"),
                "ChangedPass456!",
                "ChangedPass456!"
            )
            .await,
        Err(user_center::service::ManagementError::Invalid(
            "invalid_credentials"
        ))
    ));
    assert!(
        state
            .session_service()
            .validate(&changing)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        account
            .change_password(
                &session,
                Some("OriginalPass123!"),
                "ChangedPass456!",
                "ChangedPass456!"
            )
            .await
            .is_ok()
    );
    assert!(
        state
            .session_service()
            .validate(&changing)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        state
            .session_service()
            .validate(&raw_old)
            .await
            .unwrap()
            .is_none()
    );
    guard.shutdown().await;
    assert!(matches!(
        user_center::service::contact::ContactVerificationService::new(&state)
            .load_active_user(user)
            .await,
        Err(user_center::service::contact::ContactError::ServiceUnavailable)
    ));
    let (jar, csrf_token) = state.web_security().ensure_csrf(CookieJar::new());
    let response = user_center::web::sso::register::post(
        State(state.clone()),
        jar,
        // Per-fixture source and email avoid consuming a previous run's hourly budgets.
        pero_api_axum::extractor::ClientIp(Some(
            format!("{}/128", std::net::Ipv6Addr::from(user.as_u128()))
                .parse()
                .unwrap(),
        )),
        Form(user_center::web::sso::register::Input {
            csrf_token,
            email: format!("dependency-{user}@example.com"),
            ..Default::default()
        }),
    )
    .await;
    assert_eq!(
        response.status(),
        axum::http::StatusCode::SERVICE_UNAVAILABLE
    );
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
