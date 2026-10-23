#[path = "support/database.rs"]
mod database;
use axum::{
    Form,
    extract::{Path, State},
};
use axum_extra::extract::CookieJar;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use user_center::{
    config::AppConfig,
    state::app::AppState,
    web::dashboard::{dto::ProviderFormData, providers},
};

#[tokio::test]
#[ignore = "requires dedicated PERO_TEST_DATABASE_URL and PERO_TEST_REDIS_URL"]
async fn wechat_configuration_roundtrip_and_activation_validation() {
    let fixture = database::DatabaseFixture::new().await;
    let config: AppConfig = serde_json::from_value(serde_json::json!({
        "database":{"url":fixture.url,"encrypt_key":"test-only-key","min_connections":1},
        "redis":{"url":std::env::var("PERO_TEST_REDIS_URL").unwrap()},
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
    let (jar, csrf) = state.web_security().ensure_csrf(CookieJar::new());
    let form = || ProviderFormData {
        csrf_token: csrf.clone(),
        code: "wechat".into(),
        name: "WeChat".into(),
        kind: "wechat".into(),
        authorization_endpoint: "https://open.weixin.qq.com/connect/qrconnect".into(),
        token_endpoint: "https://api.weixin.qq.com/sns/oauth2/access_token".into(),
        userinfo_endpoint: "https://api.weixin.qq.com/sns/userinfo".into(),
        client_id: "test-appid".into(),
        client_secret: "test-secret".into(),
        enabled: true,
        ..Default::default()
    };
    for code in [".", ".."] {
        let mut invalid = form();
        invalid.code = code.into();
        assert_eq!(
            providers::create(State(state.clone()), jar.clone(), Form(invalid))
                .await
                .status(),
            400
        );
    }
    assert_eq!(
        providers::create(State(state.clone()), jar.clone(), Form(form()))
            .await
            .status(),
        200
    );
    use user_center::db::entity::identity_providers as ip;
    let row = ip::Entity::find()
        .filter(ip::Column::Code.eq("wechat"))
        .one(&db)
        .await
        .unwrap()
        .unwrap();
    let mut changed = form();
    changed.name = "WeChat renamed".into();
    changed.client_secret = String::new();
    let response = providers::update(
        State(state.clone()),
        jar.clone(),
        Path(row.id),
        Form(changed),
    )
    .await;
    let body = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&body).unwrap()["code"],
        0
    );
    let provider = user_center::db::helper::provider::find_provider_with_secret(&db, row.id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(provider.client_secret.as_deref(), Some("test-secret"));
    assert_eq!(provider.provider.client_id.as_deref(), Some("test-appid"));
    // Repointing an existing namespace would reuse other users' upstream subjects.
    let mut oidc = form();
    oidc.code = "oidc".into();
    oidc.kind = "oidc".into();
    oidc.issuer = "https://old.example.test".into();
    oidc.jwks_uri = "https://old.example.test/jwks".into();
    oidc.scopes = "openid".into();
    providers::create(State(state.clone()), jar.clone(), Form(oidc.clone())).await;
    let oidc_id = ip::Entity::find()
        .filter(ip::Column::Code.eq("oidc"))
        .one(&db)
        .await
        .unwrap()
        .unwrap()
        .id;
    oidc.issuer = "https://new.example.test".into();
    assert_eq!(
        providers::update(State(state.clone()), jar.clone(), Path(oidc_id), Form(oidc))
            .await
            .status(),
        400
    );
    for field in ["client_id", "userinfo_endpoint"] {
        let mut repointed = form();
        if field == "client_id" {
            repointed.client_id = "different-appid".into();
        } else {
            repointed.userinfo_endpoint = "https://new.example.test/userinfo".into();
        }
        assert_eq!(
            providers::update(
                State(state.clone()),
                jar.clone(),
                Path(row.id),
                Form(repointed)
            )
            .await
            .status(),
            400
        );
    }
    let service = state.social_service();
    let prepared = service
        .prepare_login_state(&provider.provider, "wechat", None, "/dashboard")
        .await
        .ok()
        .unwrap();
    let url = url::Url::parse(&prepared.authorize_url).unwrap();
    assert!(
        url.query_pairs()
            .any(|(k, v)| k == "appid" && v == "test-appid")
    );
    let mut invalid = provider.provider.clone();
    invalid.client_id = None;
    assert!(user_center::service::provider::validate_configuration(&invalid, true).is_err());
    invalid.enabled = false;
    assert!(user_center::service::provider::validate_configuration(&invalid, true).is_ok());
    invalid.token_endpoint = Some("https://127.0.0.1/token".into());
    assert!(user_center::service::provider::validate_configuration(&invalid, true).is_err());

    // A callback or cached account-link flow may outlive provider disablement.
    use sea_orm::{ConnectionTrait, DbBackend, Statement};
    use user_center::service::password::PasswordIdentityService;
    let user_id = uuid::Uuid::now_v7();
    let local_id = uuid::Uuid::now_v7();
    db.execute_raw(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "INSERT INTO users(id,username) VALUES($1,'provider_guard_user')",
        [user_id.into()],
    ))
    .await
    .unwrap();
    db.execute_raw(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "INSERT INTO identity_providers(id,code,name,kind,issuer) VALUES($1,'local','Local','local','https://issuer.example.test')",
        [local_id.into()],
    ))
    .await
    .unwrap();
    let password = PasswordIdentityService::create(
        &db,
        user_id,
        local_id,
        user_id.to_string(),
        "OriginalPass123!",
        time::OffsetDateTime::now_utc(),
    )
    .await
    .unwrap();
    // Reject enc before changing the local provider's active signing key.
    let (key_jar, key_csrf) = state.web_security().ensure_csrf(CookieJar::new());
    let key_form = || user_center::web::dashboard::dto::KeyForm {
        csrf_token: key_csrf.clone(),
        kid: "local-signing".into(),
        algorithm: "RS256".into(),
        key_use: "sig".into(),
        public_key_pem: include_str!("../../../tests/fixtures/rsa-public.pem").into(),
        private_key_pem: include_str!("../../../tests/fixtures/rsa-private.pem").into(),
        certificate_pem: String::new(),
        active: true,
        not_before: String::new(),
        expires_at: String::new(),
    };
    assert_eq!(
        user_center::web::dashboard::keys::create(
            State(state.clone()),
            key_jar.clone(),
            Path(local_id),
            Form(key_form())
        )
        .await
        .status(),
        200
    );
    let mut invalid = key_form();
    invalid.kid = "unsupported-encryption".into();
    invalid.key_use = "enc".into();
    assert_eq!(
        user_center::web::dashboard::keys::create(
            State(state.clone()),
            key_jar,
            Path(local_id),
            Form(invalid)
        )
        .await
        .status(),
        400
    );
    assert_eq!(
        user_center::db::helper::signing_key::require_active_signing_key(&db)
            .await
            .unwrap()
            .kid,
        "local-signing"
    );

    let link = user_center::cache::key::SocialLinkValue {
        redirect: "/dashboard".into(),
        auth_request_id: None,
        user_id: user_id.to_string(),
        provider_id: row.id.to_string(),
        provider_code: "wechat".into(),
        provider_name: "WeChat".into(),
        subject: "wechat-user".into(),
        email: None,
        email_verified: false,
        name: None,
        avatar_url: None,
    };
    let identity_id = service
        .link_social_identity(&password, row.id, &link)
        .await
        .ok()
        .unwrap();
    let sessions = state.session_service();
    assert!(
        sessions
            .create_social(user_id, identity_id, row.id, None, None)
            .await
            .is_ok()
    );
    // The server-side login state retains the destination through the callback.
    let callback_state = AppState::new(
        (*state.config).clone(),
        db.clone(),
        pero_cache_redis::RedisCacheStore::from_config(&state.config.redis).unwrap(),
        ProviderHttp,
    );
    let jar = CookieJar::new().add(axum_extra::extract::cookie::Cookie::new(
        state.cookie_factory().social_state_cookie_name(),
        prepared.state_hash,
    ));
    let response = user_center::web::sso::social::callback(
        State(callback_state),
        jar,
        pero_api_axum::extractor::ClientIp(None),
        Path("wechat".into()),
        axum::extract::Query(user_center::web::sso::social::CallbackParams {
            code: Some("one-use-code".into()),
            state: Some(prepared.state_token),
            error: None,
        }),
    )
    .await;
    assert_eq!(response.headers()["location"], "/dashboard");
    let pending = service
        .create_social_link(
            &provider,
            &user_center::service::social::SocialUserInfo {
                authenticated_at: None,
                sub: "another-subject".into(),
                email: None,
                email_verified: false,
                name: None,
                avatar_url: None,
                profile_extra: serde_json::json!({}),
            },
            &user_center::db::entity::users::Entity::find_by_id(user_id)
                .one(&db)
                .await
                .unwrap()
                .unwrap(),
            None,
            "/dashboard",
        )
        .await
        .ok()
        .unwrap();
    assert_eq!(
        service
            .load_social_link(&pending)
            .await
            .ok()
            .unwrap()
            .unwrap()
            .redirect,
        "/dashboard"
    );
    service.delete_social_link_cache(&pending).await;

    // Optional contact reservations must not prevent either new identity from registering.
    let mut registration_config = (*state.config).clone();
    registration_config.notification.endpoint = "https://notify.example.test".into();
    let registration_state = AppState::new(
        registration_config,
        db.clone(),
        pero_cache_redis::RedisCacheStore::from_config(&state.config.redis).unwrap(),
        ProviderHttp,
    );
    let registration = registration_state.social_service();
    let info = |subject: &str| user_center::service::social::SocialUserInfo {
        authenticated_at: None,
        sub: subject.into(),
        email: Some("shared-unverified@example.test".into()),
        email_verified: false,
        name: None,
        avatar_url: None,
        profile_extra: serde_json::json!({}),
    };
    let (first, second) = tokio::join!(
        registration.register_user(&provider, info("new-social-user-1"), None),
        registration.register_user(&provider, info("new-social-user-2"), None),
    );
    for result in [first, second] {
        let (user, _) = result.unwrap();
        assert!(user.email.is_none());
        assert!(
            user_center::db::entity::users::Entity::find_by_id(user.id)
                .one(&db)
                .await
                .unwrap()
                .is_some()
        );
    }
    let queued = db
        .query_one_raw(Statement::from_string(
            DbBackend::Postgres,
            "SELECT count(*) AS n FROM notification_outbox WHERE kind='verify_contact'".to_owned(),
        ))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(queued.try_get::<i64>("", "n").unwrap(), 1);

    // Historical verified records and expired reservations must both allow a fresh claim.
    for (subject, update, expected) in [
        (
            "released-email",
            "status='verified',verified_at=now()",
            2_i64,
        ),
        (
            "expired-email",
            "requested_at=now()-interval '30 minutes',expires_at=now()-interval '1 minute'",
            3_i64,
        ),
    ] {
        db.execute_unprepared(&format!("UPDATE contact_change_requests SET {update} WHERE new_value='shared-unverified@example.test' AND status='pending'")).await.unwrap();
        registration
            .register_user(&provider, info(subject), None)
            .await
            .unwrap();
        let queued = db
            .query_one_raw(Statement::from_string(
                DbBackend::Postgres,
                "SELECT count(*) AS n FROM notification_outbox WHERE kind='verify_contact'"
                    .to_owned(),
            ))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(queued.try_get::<i64>("", "n").unwrap(), expected);
    }

    user_center::service::provider::toggle_enabled(&db, row.id)
        .await
        .unwrap();
    let accepted_link = service
        .link_social_identity(&password, row.id, &link)
        .await
        .is_ok();
    let accepted_session = sessions
        .create_social(user_id, identity_id, row.id, None, None)
        .await
        .is_ok();
    assert!(
        !accepted_link && !accepted_session,
        "disabled provider accepted link={accepted_link}, session={accepted_session}"
    );
    guard.shutdown().await;
    fixture.cleanup().await;
}

struct ProviderHttp;
#[async_trait::async_trait]
impl pero_http_client_core::HttpClient for ProviderHttp {
    async fn send(
        &self,
        _: http::Request<Vec<u8>>,
    ) -> pero_http_client_core::HttpClientResult<pero_http_client_core::HttpResponse> {
        Ok(pero_http_client_core::HttpResponse {
            status: http::StatusCode::OK,
            headers: http::HeaderMap::new(),
            body: serde_json::to_vec(
                &serde_json::json!({"access_token":"upstream-token","openid":"wechat-user"}),
            )
            .unwrap(),
        })
    }
}
