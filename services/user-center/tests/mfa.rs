#[path = "support/database.rs"]
mod database;
use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use tower::ServiceExt;
use user_center::{service::security as sec, state::app::AppState};
use uuid::Uuid;
struct Browser {
    cookies: std::collections::BTreeMap<String, String>,
    csrf: String,
}
impl Browser {
    async fn call(
        &mut self,
        app: &axum::Router,
        path: &str,
        form: Option<&[(&str, &str)]>,
    ) -> (StatusCode, serde_json::Value) {
        let cookie = self
            .cookies
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("; ");
        let mut request = Request::builder()
            .uri(path)
            .header("Accept", "application/json")
            .header("Cookie", cookie);
        let body = if let Some(form) = form {
            request = request
                .method("POST")
                .header("Content-Type", "application/x-www-form-urlencoded");
            let mut ser = url::form_urlencoded::Serializer::new(String::new());
            ser.append_pair("csrf_token", &self.csrf);
            for (k, v) in form {
                ser.append_pair(k, v);
            }
            ser.finish()
        } else {
            String::new()
        };
        let response = app
            .clone()
            .oneshot(request.body(Body::from(body)).unwrap())
            .await
            .unwrap();
        let status = response.status();
        for value in response.headers().get_all("set-cookie") {
            let part = value.to_str().unwrap().split(';').next().unwrap();
            let (k, v) = part.split_once('=').unwrap();
            self.cookies.insert(k.into(), v.into());
        }
        let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let value: serde_json::Value = serde_json::from_slice(&body)
            .unwrap_or_else(|_| panic!("{status}: {}", String::from_utf8_lossy(&body)));
        if let Some(csrf) = value["data"]["csrf_token"].as_str() {
            self.csrf = csrf.into();
        }
        (status, value)
    }
}
#[tokio::test]
#[ignore = "requires dedicated PostgreSQL and Redis"]
async fn mfa_enrollment_challenge_recovery_and_admin_boundary() {
    let fixture = database::DatabaseFixture::new().await;
    let cfg:user_center::config::AppConfig=serde_json::from_value(serde_json::json!({"database":{"url":fixture.url,"encrypt_key":"mfa-test-key","min_connections":1,"max_connections":8},"redis":{"url":std::env::var("PERO_TEST_REDIS_URL").unwrap()},"sso":{"cookie_signing_secret":"mfa-test-signing-secret-at-least-32-bytes"}})).unwrap();
    let (db, guard) = user_center::db::init::init_db(&cfg).await.unwrap();
    fixture.migrate(&db).await;
    let cache = pero_cache_redis::RedisCacheStore::from_config(&cfg.redis).unwrap();
    let http = pero_http_client_reqwest::ReqwestHttpClient::from_config(&cfg.http_config).unwrap();
    let state = AppState::new(cfg, db.clone(), cache, http);
    let user = Uuid::now_v7();
    sec::execute(
        &db,
        "INSERT INTO users(id,username) VALUES($1,'mfa-user')",
        vec![user.into()],
    )
    .await
    .unwrap();
    sec::execute(
        &db,
        "INSERT INTO admin_roles(user_id,role) VALUES($1,'super_admin')",
        vec![user.into()],
    )
    .await
    .unwrap();
    let (token, initial_session) = state
        .session_service()
        .create(user, None, None, None, None)
        .await
        .unwrap();
    let app = user_center::router::build(state.clone());
    let response = user_center::web::login_flow::finish_login(
        &state,
        axum_extra::extract::CookieJar::new(),
        &token,
        "/dashboard/apps?page=2",
    )
    .await;
    assert_eq!(
        response.headers()["location"],
        "/sso/mfa?redirect=%2Fdashboard%2Fapps%3Fpage%3D2"
    );
    let mut b = Browser {
        cookies: [("pero_sso".into(), token)].into(),
        csrf: String::new(),
    };
    assert!(
        !sec::recent(
            &db,
            initial_session,
            state.config.sso.session_idle_ttl_seconds
        )
        .await
        .unwrap()
    );
    b.call(&app, "/account/security", None).await;
    // OIDC-only administrators can arrive with an old upstream auth_time.
    // Forced OIDC authentication must remain reachable before first enrollment.
    let oidc_provider = Uuid::now_v7();
    let oidc_identity = Uuid::now_v7();
    sec::execute(&db,"INSERT INTO identity_providers(id,code,name,kind,issuer,authorization_endpoint,token_endpoint,userinfo_endpoint,jwks_uri,client_id,scopes) VALUES($1,'enrollment-oidc','OIDC','oidc','https://idp.example.test','https://idp.example.test/authorize','https://idp.example.test/token','https://idp.example.test/userinfo','https://idp.example.test/keys','pero',ARRAY['openid'])",vec![oidc_provider.into()]).await.unwrap();
    sec::execute(&db,"INSERT INTO identities(id,user_id,provider_id,kind,subject) VALUES($1,$2,$3,'oauth','bound-subject')",vec![oidc_identity.into(),user.into(),oidc_provider.into()]).await.unwrap();
    sec::execute(
        &db,
        "UPDATE sso_sessions SET created_at=now()-interval '10 minutes',authenticated_at=now()-interval '10 minutes',reauthenticated_at=now()-interval '10 minutes' WHERE id=$1",
        vec![initial_session.into()],
    )
    .await
    .unwrap();
    let (_, reauth_page) = b.call(&app, "/account/reauth", None).await;
    assert_eq!(
        reauth_page["view"], "SecurityView",
        "First OIDC enrollment must remain reachable"
    );
    let (_, start) = b
        .call(&app, "/account/reauth/enrollment-oidc", Some(&[]))
        .await;
    let redirect = start["redirect"].as_str().unwrap();
    assert!(
        redirect.starts_with("https://idp.example.test/authorize?"),
        "{start}"
    );
    let authorize = url::Url::parse(redirect).unwrap();
    assert_eq!(authorize.host_str(), Some("idp.example.test"));
    assert!(
        authorize
            .query_pairs()
            .any(|(k, v)| k == "prompt" && v == "login")
    );
    assert!(
        authorize
            .query_pairs()
            .any(|(k, v)| k == "max_age" && v == "0")
    );
    use sea_orm::EntityTrait;
    let initial = user_center::db::entity::sso_sessions::Entity::find_by_id(initial_session)
        .one(&db)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        user_center::service::mfa::record_oidc_reauthentication(
            &state,
            &initial,
            oidc_provider,
            "wrong-subject",
            Some(time::OffsetDateTime::now_utc()),
        )
        .await,
        Err(user_center::service::ManagementError::Invalid(
            "invalid_credentials"
        ))
    ));
    for authenticated_at in [
        None,
        Some(time::OffsetDateTime::now_utc() - time::Duration::seconds(sec::RECENT_SECONDS + 60)),
    ] {
        assert!(matches!(
            user_center::service::mfa::record_oidc_reauthentication(
                &state,
                &initial,
                oidc_provider,
                "bound-subject",
                authenticated_at,
            )
            .await,
            Err(user_center::service::ManagementError::Invalid(
                "reauth_required"
            ))
        ));
    }
    let proof_at = time::OffsetDateTime::now_utc() - time::Duration::minutes(1);
    user_center::service::mfa::record_oidc_reauthentication(
        &state,
        &initial,
        oidc_provider,
        "bound-subject",
        Some(proof_at),
    )
    .await
    .unwrap();
    let proof = user_center::db::entity::sso_sessions::Entity::find_by_id(initial_session)
        .one(&db)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        proof.oidc_reauthenticated_at.unwrap().unix_timestamp(),
        proof_at.unix_timestamp(),
        "Receiving a callback must not refresh upstream auth_time"
    );
    assert!(
        state
            .session_service()
            .validate(b.cookies.get("pero_sso").unwrap())
            .await
            .unwrap()
            .is_some(),
        "Primary authentication remains usable for ordinary applications"
    );
    // An unenrolled administrator can refresh primary proof without receiving
    // MFA assurance; this allows first enrollment after the original login ages.
    let (_, reauth) = b
        .call(&app, "/account/reauth", Some(&[("action", "reauth")]))
        .await;
    assert!(reauth["redirect"].is_string(), "{reauth}");
    let refreshed = state
        .session_service()
        .validate(b.cookies.get("pero_sso").unwrap())
        .await
        .unwrap()
        .unwrap();
    let row = user_center::db::entity::sso_sessions::Entity::find_by_id(refreshed.id)
        .one(&db)
        .await
        .unwrap()
        .unwrap();
    assert!(
        row.mfa_verified_at.is_none(),
        "Primary proof must not manufacture an MFA verification"
    );
    assert_eq!(
        row.reauthenticated_at.unwrap().unix_timestamp(),
        proof_at.unix_timestamp()
    );
    assert!(
        !sec::recent(&db, row.id, state.config.sso.session_idle_ttl_seconds)
            .await
            .unwrap()
    );
    state
        .cache
        .del(
            user_center::cache::key::mfa_attempt
                .key(&user.to_string())
                .unwrap(),
        )
        .await
        .unwrap();
    b.call(&app, "/account/security", None).await;
    let (_, setup) = b
        .call(&app, "/account/security", Some(&[("action", "setup")]))
        .await;
    assert!(setup["data"]["error"].as_str() == Some(""), "{setup}");
    let secret = setup["data"]["secret"].as_str().unwrap();
    assert!(!secret.is_empty(), "{setup}");
    let otp = sec::totp(secret, "test").unwrap();
    let now = time::OffsetDateTime::now_utc().unix_timestamp() as u64;
    let code = otp.generate(now).to_string();
    let (_, enabled) = b
        .call(
            &app,
            "/account/security",
            Some(&[("action", "enable"), ("code", &code)]),
        )
        .await;
    let recovery = enabled["data"]["codes"][0].as_str().unwrap().to_string();
    assert_eq!(enabled["data"]["codes"].as_array().unwrap().len(), 8);
    let enrolled = state
        .session_service()
        .validate(b.cookies.get("pero_sso").unwrap())
        .await
        .unwrap()
        .unwrap();
    assert!(
        enrolled.authenticated_at
            > time::OffsetDateTime::now_utc() - time::Duration::seconds(sec::RECENT_SECONDS),
        "Completed enrollment must retain the new upstream authentication time"
    );
    let (token, pending_id) = state
        .session_service()
        .create(user, None, None, None, None)
        .await
        .unwrap();
    let (_, sessions) = b.call(&app, "/account/sessions", None).await;
    let pending = sessions["data"]["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["id"] == pending_id.to_string());
    assert!(
        pending.is_some(),
        "Pending MFA sessions must remain visible and revocable: {sessions}"
    );
    assert_eq!(pending.unwrap()["authentication_pending"], true);
    assert!(
        state
            .session_service()
            .validate(&token)
            .await
            .unwrap()
            .is_some()
    );
    b.cookies.insert("pero_sso".into(), token.clone());
    let (_, restart) = b.call(&app, "/sso/social/missing/login", None).await;
    assert!(
        restart["redirect"]
            .as_str()
            .unwrap()
            .starts_with("/sso/error"),
        "An incomplete MFA session must not block restarting upstream login"
    );
    b.call(&app, "/sso/mfa", None).await;
    let (status, denied) = b
        .call(&app, "/account/reauth/enrollment-oidc", Some(&[]))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{denied}");
    assert_eq!(denied["error"], "unauthorized");
    let (_, replayed) = b
        .call(
            &app,
            "/sso/mfa",
            Some(&[("action", "verify"), ("code", &code)]),
        )
        .await;
    assert_eq!(replayed["data"]["error"], "invalid_mfa_code");
    let (_, recovered) = b
        .call(
            &app,
            "/sso/mfa",
            Some(&[("action", "recover"), ("code", &recovery)]),
        )
        .await;
    assert_eq!(recovered["data"]["recovery"], true);
    let (status, denied) = b
        .call(&app, "/account/reauth/enrollment-oidc", Some(&[]))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{denied}");
    assert_eq!(denied["error"], "unauthorized");
    assert!(
        state
            .session_service()
            .validate(b.cookies.get("pero_sso").unwrap())
            .await
            .unwrap()
            .is_none()
    );
    let f = sec::factor(&db, user).await.unwrap().unwrap();
    assert!(
        !f.recovery_hashes
            .contains(&pero_utils::crypto::sha256_hex(&recovery))
    );
    b.call(&app, "/account/security", Some(&[("action", "setup")]))
        .await;
    // A second password-only session cannot take over recovery enrollment.
    let (other, _) = state
        .session_service()
        .create(user, None, None, None, None)
        .await
        .unwrap();
    b.cookies.insert("pero_sso".into(), other);
    b.call(&app, "/account/security", None).await;
    let (_, denied) = b
        .call(&app, "/account/security", Some(&[("action", "setup")]))
        .await;
    assert_eq!(denied["data"]["error"], "reauth_required");
    let staged = sec::factor(&db, user).await.unwrap().unwrap();
    assert!(
        staged.enabled,
        "Staging a replacement must preserve the active factor"
    );
    assert_eq!(
        staged.recovery_hashes.len(),
        7,
        "Unused codes must survive interrupted enrollment"
    );
    let second_code = enabled["data"]["codes"][1].as_str().unwrap();
    let (_, again) = b
        .call(
            &app,
            "/sso/mfa",
            Some(&[("action", "recover"), ("code", second_code)]),
        )
        .await;
    assert_eq!(again["data"]["recovery"], true, "{again}");
    let raw = b.cookies.get("pero_sso").unwrap().clone();
    b.call(&app, "/account/logout", Some(&[])).await;
    use sea_orm::{ColumnTrait, QueryFilter};
    let logged_out = user_center::db::entity::sso_sessions::Entity::find()
        .filter(
            user_center::db::entity::sso_sessions::Column::TokenHash
                .eq(pero_utils::crypto::sha256_hex(&raw)),
        )
        .one(&db)
        .await
        .unwrap()
        .unwrap();
    assert!(
        logged_out.revoked_at.is_some(),
        "Logout must revoke incomplete recovery sessions"
    );
    let (token, _) = state
        .session_service()
        .create(user, None, None, None, None)
        .await
        .unwrap();
    b.cookies.insert("pero_sso".into(), token);
    b.call(&app, "/sso/mfa", None).await;
    let third_code = enabled["data"]["codes"][2].as_str().unwrap();
    let (_, again) = b
        .call(
            &app,
            "/sso/mfa",
            Some(&[("action", "recover"), ("code", third_code)]),
        )
        .await;
    assert_eq!(again["data"]["recovery"], true);
    b.call(&app, "/account/security", Some(&[("action", "setup")]))
        .await;
    let (_, view) = b.call(&app, "/account/security", None).await;
    let new_otp = sec::totp(view["data"]["secret"].as_str().unwrap(), "test").unwrap();
    let code = new_otp
        .generate(time::OffsetDateTime::now_utc().unix_timestamp() as u64)
        .to_string();
    let (_, done) = b
        .call(
            &app,
            "/account/security",
            Some(&[("action", "enable"), ("code", &code)]),
        )
        .await;
    assert_eq!(done["data"]["recovery"], false);
    assert!(
        state
            .session_service()
            .validate(b.cookies.get("pero_sso").unwrap())
            .await
            .unwrap()
            .is_some()
    );
    // Exercise redirects through the router: rotating the DB session must also
    // replace the browser cookie and invalidate the previous credential.
    state
        .cache
        .del(
            user_center::cache::key::mfa_attempt
                .key(&user.to_string())
                .unwrap(),
        )
        .await
        .unwrap();
    let provider = Uuid::now_v7();
    sec::execute(
        &db,
        "INSERT INTO identity_providers(id,code,name,kind,issuer) VALUES($1,'local','Local','local','https://issuer.example.test')",
        vec![provider.into()],
    )
    .await
    .unwrap();
    user_center::service::password::PasswordIdentityService::create(
        &db,
        user,
        provider,
        user.to_string(),
        "OriginalPass123!",
        time::OffsetDateTime::now_utc(),
    )
    .await
    .unwrap();
    let (primary, primary_id) = state
        .session_service()
        .create(user, None, None, None, None)
        .await
        .unwrap();
    sec::execute(
        &db,
        "UPDATE sso_sessions SET reauthenticated_at=NULL WHERE id=$1",
        vec![primary_id.into()],
    )
    .await
    .unwrap();
    b.cookies.insert("pero_sso".into(), primary.clone());
    b.call(&app, "/sso/mfa", None).await;
    for action in ["verify", "reauth"] {
        // Reset only the fixture's replay marker so both transitions can use
        // the real current OTP without a wall-clock sleep.
        sec::execute(
            &db,
            "UPDATE user_mfa SET last_step=-1 WHERE user_id=$1",
            vec![user.into()],
        )
        .await
        .unwrap();
        let code = new_otp
            .generate(time::OffsetDateTime::now_utc().unix_timestamp() as u64)
            .to_string();
        let previous = b.cookies.get("pero_sso").unwrap().clone();
        let path = if action == "verify" {
            "/sso/mfa"
        } else {
            "/account/reauth"
        };
        b.call(&app, path, None).await;
        let (_, response) = b
            .call(
                &app,
                path,
                Some(&[
                    ("action", action),
                    ("code", &code),
                    ("password", "OriginalPass123!"),
                    ("redirect", "/account/security"),
                ]),
            )
            .await;
        assert_eq!(response["redirect"], "/account/security", "{response}");
        assert_ne!(
            b.cookies.get("pero_sso").unwrap(),
            &previous,
            "{action} must return its rotated cookie"
        );
        assert!(
            state
                .session_service()
                .validate(&previous)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            state
                .session_service()
                .validate(b.cookies.get("pero_sso").unwrap())
                .await
                .unwrap()
                .is_some()
        );
        let session = state
            .session_service()
            .validate(b.cookies.get("pero_sso").unwrap())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            sec::recent(&db, session.id, state.config.sso.session_idle_ttl_seconds)
                .await
                .unwrap(),
            action == "reauth",
            "TOTP alone cannot manufacture a primary credential proof"
        );
    }
    sec::execute(
        &db,
        "UPDATE admin_roles SET role='admin' WHERE user_id=$1",
        vec![user.into()],
    )
    .await
    .unwrap();
    sec::execute(
        &db,
        "INSERT INTO admin_permission_state(user_id) VALUES($1)",
        vec![user.into()],
    )
    .await
    .unwrap();
    let (status, _) = b.call(&app, "/dashboard/apps", None).await;
    assert_eq!(status, StatusCode::OK);
    sec::execute(
        &db,
        "DELETE FROM admin_roles WHERE user_id=$1",
        vec![user.into()],
    )
    .await
    .unwrap();
    let (status, _) = b.call(&app, "/dashboard/apps", None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    sec::execute(
        &db,
        "INSERT INTO admin_roles(user_id,role) VALUES($1,'super_admin')",
        vec![user.into()],
    )
    .await
    .unwrap();
    b.call(&app, "/dashboard/admins", None).await;
    let (status, v) = b
        .call(
            &app,
            "/dashboard/admins",
            Some(&[("username", "mfa-user"), ("role", "remove")]),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{v}");
    assert_eq!(v["error"], "cannot_change_own_admin_role");
    let optional = Uuid::now_v7();
    sec::execute(
        &db,
        "INSERT INTO users(id,username) VALUES($1,'optional-mfa')",
        vec![optional.into()],
    )
    .await
    .unwrap();
    sec::execute(&db,"INSERT INTO user_mfa(user_id,secret_enc) VALUES($1,pgp_sym_encrypt('GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ',current_setting('app.encrypt_key')))",vec![optional.into()]).await.unwrap();
    let (optional_token, optional_id) = state
        .session_service()
        .create(optional, None, None, None, None)
        .await
        .unwrap();
    assert!(
        state
            .session_service()
            .validate(&optional_token)
            .await
            .unwrap()
            .is_some()
    );
    sec::execute(&db,"INSERT INTO identities(id,user_id,provider_id,kind,subject) VALUES($1,$2,$3,'oauth','optional-subject')",vec![Uuid::now_v7().into(),optional.into(),oidc_provider.into()]).await.unwrap();
    let optional_session = user_center::db::entity::sso_sessions::Entity::find_by_id(optional_id)
        .one(&db)
        .await
        .unwrap()
        .unwrap();
    let proof_at = time::OffsetDateTime::now_utc() - time::Duration::minutes(1);
    user_center::service::mfa::record_oidc_reauthentication(
        &state,
        &optional_session,
        oidc_provider,
        "optional-subject",
        Some(proof_at),
    )
    .await
    .unwrap();
    b.cookies.insert("pero_sso".into(), optional_token);
    b.call(&app, "/account/reauth", None).await;
    let (_, response) = b
        .call(
            &app,
            "/account/reauth",
            Some(&[("action", "reauth"), ("redirect", "/account/security")]),
        )
        .await;
    assert_eq!(response["redirect"], "/account/security", "{response}");
    let reauthenticated = state
        .session_service()
        .validate(b.cookies.get("pero_sso").unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        reauthenticated.authenticated_at.unix_timestamp(),
        proof_at.unix_timestamp(),
        "Completing OIDC reauthentication must retain the original authentication time"
    );
    drop(app);
    drop(state);
    db.close().await.unwrap();
    drop(guard);
    fixture.cleanup().await;
}

#[tokio::test]
#[ignore = "requires dedicated PostgreSQL and Redis"]
async fn password_login_challenges_before_redirect_and_activity_is_visible() {
    use user_center::service::password::PasswordIdentityService;
    let fixture = database::DatabaseFixture::new().await;
    let cfg: user_center::config::AppConfig = serde_json::from_value(serde_json::json!({
        "database":{"url":fixture.url,"encrypt_key":"login-activity-test-key","min_connections":1},
        "redis":{"url":std::env::var("PERO_TEST_REDIS_URL").unwrap()},
        "sso":{"cookie_signing_secret":"login-activity-test-signing-secret-long-enough"}
    }))
    .unwrap();
    let (db, guard) = user_center::db::init::init_db(&cfg).await.unwrap();
    let cache = pero_cache_redis::RedisCacheStore::from_config(&cfg.redis).unwrap();
    let http = pero_http_client_reqwest::ReqwestHttpClient::from_config(&cfg.http_config).unwrap();
    let state = AppState::new(cfg, db.clone(), cache, http);
    let user = Uuid::now_v7();
    let provider = Uuid::now_v7();
    sec::execute(
        &db,
        "INSERT INTO users(id,username) VALUES($1,'activity-user')",
        vec![user.into()],
    )
    .await
    .unwrap();
    sec::execute(
        &db,
        "INSERT INTO identity_providers(id,code,name,kind,issuer) VALUES($1,'local','Local','local','http://localhost:8080')",
        vec![provider.into()],
    )
    .await
    .unwrap();
    let password = PasswordIdentityService::hash_password("ActivityPass123!")
        .await
        .unwrap();
    PasswordIdentityService::create_hashed(
        &db,
        user,
        provider,
        user.to_string(),
        password,
        time::OffsetDateTime::now_utc(),
    )
    .await
    .unwrap();
    sec::execute(
        &db,
        "INSERT INTO admin_roles(user_id,role) VALUES($1,'super_admin')",
        vec![user.into()],
    )
    .await
    .unwrap();
    let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    sec::execute(&db,"INSERT INTO user_mfa(user_id,secret_enc,enabled) VALUES($1,pgp_sym_encrypt($2,current_setting('app.encrypt_key')),true)",vec![user.into(),secret.into()]).await.unwrap();
    let app = user_center::router::build(state.clone());
    let mut browser = Browser {
        cookies: Default::default(),
        csrf: String::new(),
    };
    browser.call(&app, "/account/login", None).await;
    let (_, login) = browser
        .call(
            &app,
            "/account/login",
            Some(&[
                ("identifier_type", "username"),
                ("identifier", "activity-user"),
                ("password", "ActivityPass123!"),
                ("redirect", "/dashboard/events"),
            ]),
        )
        .await;
    assert_eq!(login["redirect"], "/sso/mfa?redirect=%2Fdashboard%2Fevents");
    let (_, gate) = browser.call(&app, "/dashboard/events", None).await;
    assert_eq!(gate["redirect"], "/sso/mfa?redirect=%2Fdashboard%2Fevents");
    let (_, challenge) = browser
        .call(&app, gate["redirect"].as_str().unwrap(), None)
        .await;
    assert_eq!(challenge["data"]["pending"], true);
    assert!(
        state
            .session_service()
            .validate(browser.cookies.get("pero_sso").unwrap())
            .await
            .unwrap()
            .is_some()
    );
    let code = sec::totp(secret, "activity-user")
        .unwrap()
        .generate(time::OffsetDateTime::now_utc().unix_timestamp() as u64)
        .to_string();
    let (_, verified) = browser
        .call(
            &app,
            "/sso/mfa",
            Some(&[
                ("action", "verify"),
                ("code", &code),
                ("redirect", "/dashboard/events"),
            ]),
        )
        .await;
    assert_eq!(verified["redirect"], "/dashboard/events");
    for path in [
        "/account/activity",
        "/dashboard/events?event_type=login_success&q=activity",
    ] {
        let (status, activity) = browser.call(&app, path, None).await;
        assert_eq!(status, StatusCode::OK, "{activity}");
        assert_eq!(
            activity["data"]["rows"].as_array().unwrap().len(),
            1,
            "{activity}"
        );
        assert_eq!(activity["data"]["rows"][0]["username"], "activity-user");
        assert_eq!(activity["data"]["rows"][0]["event_type"], "login_success");
    }
    for role in ["super_admin", "admin", "remove"] {
        let (status, rejected) = browser
            .call(
                &app,
                "/dashboard/admins",
                Some(&[("username", "activity-user"), ("role", role)]),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{rejected}");
        assert_eq!(rejected["error"], "cannot_change_own_admin_role");
        assert!(
            state
                .session_service()
                .validate(browser.cookies.get("pero_sso").unwrap())
                .await
                .unwrap()
                .is_some()
        );
        assert_eq!(
            sec::role(&db, user).await.unwrap().as_deref(),
            Some("super_admin")
        );
    }
    let other = Uuid::now_v7();
    sec::execute(
        &db,
        "INSERT INTO users(id,username) VALUES($1,'activity-other')",
        vec![other.into()],
    )
    .await
    .unwrap();
    let (_, results) = browser
        .call(&app, "/dashboard/admins/users?q=activity", None)
        .await;
    assert_eq!(results["users"].as_array().unwrap().len(), 1);
    assert_eq!(results["users"][0]["id"], other.to_string());
    let (_, roles) = browser
        .call(&app, "/dashboard/admins?q=activity&role=super_admin", None)
        .await;
    assert_eq!(roles["data"]["current_user_id"], user.to_string());
    assert_eq!(roles["data"]["rows"].as_array().unwrap().len(), 1);
    // Per-user application settings are independent from the mandatory dashboard factor.
    let ordinary_app = Uuid::now_v7();
    let client = Uuid::now_v7();
    sec::execute(
        &db,
        "INSERT INTO apps(id,code,name) VALUES($1,$2,'Personal MFA test')",
        vec![ordinary_app.into(), ordinary_app.to_string().into()],
    )
    .await
    .unwrap();
    sec::execute(
        &db,
        "INSERT INTO user_app_access(user_id,app_id) VALUES($1,$2)",
        vec![user.into(), ordinary_app.into()],
    )
    .await
    .unwrap();
    sec::execute(&db,"INSERT INTO oauth_clients(id,app_id,identifier,secret_hash,type,redirect_uris,scopes,require_pkce) VALUES($1,$2,$3,'test-hash','confidential',ARRAY['https://client.example.test/callback'],ARRAY['openid'],false)",vec![client.into(),ordinary_app.into(),client.to_string().into()]).await.unwrap();
    let (_, applications) = browser.call(&app, "/account/applications", None).await;
    assert_eq!(applications["data"]["mfa_enabled"], true);
    assert_eq!(applications["data"]["rows"][0]["require_mfa"], false);
    let endpoint = format!("/account/applications/{ordinary_app}/mfa");
    let (status, result) = browser
        .call(&app, &endpoint, Some(&[("action", "enable_mfa")]))
        .await;
    assert_eq!(status, StatusCode::OK, "{result}");
    let (_, applications) = browser.call(&app, "/account/applications", None).await;
    assert_eq!(applications["data"]["rows"][0]["require_mfa"], true);
    // Password login for an enrolled super administrator must reach the target
    // application before applying its explicitly enabled MFA preference.
    let authorize = format!(
        "/oauth2/authorize?client_id={client}&redirect_uri=https%3A%2F%2Fclient.example.test%2Fcallback&response_type=code&scope=openid&state=personal-mfa"
    );
    browser.cookies.remove("pero_sso");
    browser.call(&app, "/account/login", None).await;
    let (_, login) = browser
        .call(
            &app,
            "/account/login",
            Some(&[
                ("identifier_type", "username"),
                ("identifier", "activity-user"),
                ("password", "ActivityPass123!"),
                ("redirect", &authorize),
            ]),
        )
        .await;
    assert_eq!(login["redirect"], authorize);
    let (_, silent) = browser
        .call(&app, &format!("{authorize}&prompt=none"), None)
        .await;
    assert!(
        silent["redirect"]
            .as_str()
            .unwrap()
            .contains("error=interaction_required"),
        "{silent}"
    );
    let (_, challenge) = browser.call(&app, &authorize, None).await;
    assert_eq!(
        challenge["redirect"],
        "/sso/mfa?redirect=%2Foauth2%2Fauthorize%2Fresume"
    );
    // Ordinary apps without the personal setting continue through consent without MFA.
    sec::execute(
        &db,
        "UPDATE user_app_access SET require_mfa=false WHERE user_id=$1 AND app_id=$2",
        vec![user.into(), ordinary_app.into()],
    )
    .await
    .unwrap();
    let (_, authorized) = browser.call(&app, &authorize, None).await;
    assert_eq!(authorized["redirect"], "/sso/consent");
    let (_, dashboard) = browser.call(&app, "/dashboard/events", None).await;
    assert_eq!(
        dashboard["redirect"],
        "/sso/mfa?redirect=%2Fdashboard%2Fevents"
    );
    // A primary-only session can reach account settings, but must finish MFA
    // before changing its application's preference through the reauth screen.
    let (_, reauth) = browser
        .call(
            &app,
            "/account/reauth?redirect=%2Faccount%2Fapplications",
            None,
        )
        .await;
    assert_eq!(
        reauth["redirect"],
        "/sso/mfa?redirect=%2Faccount%2Fapplications"
    );
    let primary = browser.cookies.get("pero_sso").unwrap().clone();
    sec::execute(
        &db,
        "UPDATE sso_sessions SET created_at=now()-interval '10 minutes' WHERE token_hash=$1",
        vec![pero_utils::crypto::sha256_hex(&primary).into()],
    )
    .await
    .unwrap();
    let (_, expired) = browser
        .call(&app, "/sso/mfa?redirect=%2Fdashboard%2Fevents", None)
        .await;
    let login_url = expired["redirect"].as_str().unwrap();
    let login = url::Url::parse(&format!("http://localhost{login_url}")).unwrap();
    assert_eq!(login.path(), "/account/login");
    let next = login
        .query_pairs()
        .find(|(key, _)| key == "redirect")
        .unwrap()
        .1
        .into_owned();
    assert_eq!(next, "/sso/mfa?redirect=%2Fdashboard%2Fevents");
    let (_, page) = browser.call(&app, login_url, None).await;
    assert_eq!(page["view"], "AccountLoginView");
    let (_, fresh) = browser
        .call(
            &app,
            "/account/login",
            Some(&[
                ("identifier_type", "username"),
                ("identifier", "activity-user"),
                ("password", "ActivityPass123!"),
                ("redirect", &next),
            ]),
        )
        .await;
    assert_eq!(fresh["redirect"], next);
    let (_, challenge) = browser.call(&app, &next, None).await;
    assert_eq!(challenge["data"]["pending"], true);
    guard.shutdown().await;
    fixture.cleanup().await;
}
