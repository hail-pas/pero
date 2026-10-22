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
    web::dashboard::{providers, template::ProviderFormData},
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
        enabled: Some("on".into()),
        ..Default::default()
    };
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
    changed.client_id = "changed-appid".into();
    changed.client_secret = String::new();
    let response = providers::update(State(state.clone()), jar, Path(row.id), Form(changed)).await;
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
    assert_eq!(
        provider.provider.client_id.as_deref(),
        Some("changed-appid")
    );
    let service = state.social_service();
    let prepared = service
        .prepare_login_state(&provider.provider, "wechat", None)
        .await
        .ok()
        .unwrap();
    let url = url::Url::parse(&prepared.authorize_url).unwrap();
    assert!(
        url.query_pairs()
            .any(|(k, v)| k == "appid" && v == "changed-appid")
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
    let link = user_center::cache::key::SocialLinkValue {
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
