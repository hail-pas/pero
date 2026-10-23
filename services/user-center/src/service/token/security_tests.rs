mod database {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/support/database.rs"
    ));
}
// Run against a fresh, dedicated PostgreSQL 18 database with migrations applied.
use super::*;
use crate::{
    config::AppConfig,
    db::entity::{oauth_clients, refresh_tokens},
    service::{
        account::AccountService,
        contact::{ContactChannel, ContactVerificationService},
        password::PasswordIdentityService,
    },
};
use sea_orm::{ConnectionTrait, DbBackend, EntityTrait, Statement, TransactionTrait};
use uuid::Uuid;

async fn sql(db: &sea_orm::DatabaseConnection, query: &str, values: Vec<sea_orm::Value>) {
    db.execute_raw(Statement::from_sql_and_values(
        DbBackend::Postgres,
        query,
        values,
    ))
    .await
    .unwrap();
}

struct SecurityFixture {
    fixture: database::DatabaseFixture,
    guard: pero_db_seaorm::DatabaseGuard,
    state: AppState,
    user: Uuid,
    app: Uuid,
    client: Uuid,
    provider: Uuid,
}

impl SecurityFixture {
    async fn new() -> Self {
        let fixture = database::DatabaseFixture::new().await;
        let config: AppConfig = serde_json::from_value(serde_json::json!({
        "database":{"url":fixture.url,"encrypt_key":"test-only-database-key","min_connections":1,"max_connections":8},
        "redis":{"url":"redis://127.0.0.1:1","connect_timeout_secs":1,"command_timeout_secs":1},
        "sso":{"cookie_signing_secret":"test-only-cookie-signing-key-long-enough","session_idle_ttl_seconds":60},
        "oidc":{"issuer":"https://issuer.example.test"},
        "password_reset":{"signing_key":"test-only-recovery-signing-key-long-enough"}
    })).unwrap();
        let (db, guard) = crate::db::init::init_db(&config).await.unwrap();
        fixture.migrate(&db).await;
        let cache = pero_cache_redis::RedisCacheStore::from_config(&config.redis).unwrap();
        let http =
            pero_http_client_reqwest::ReqwestHttpClient::from_config(&config.http_config).unwrap();
        let state = AppState::new(config, db.clone(), cache, http);
        let _router = crate::router::build(state.clone());
        let (user, app, client, provider) = (
            Uuid::now_v7(),
            Uuid::now_v7(),
            Uuid::now_v7(),
            Uuid::now_v7(),
        );
        sql(
            &db,
            "INSERT INTO users(id,username) VALUES ($1,$2)",
            vec![user.into(), user.to_string().into()],
        )
        .await;
        sql(
            &db,
            "INSERT INTO apps(id,code,name) VALUES ($1,$2,'Test')",
            vec![app.into(), app.to_string().into()],
        )
        .await;
        sql(
            &db,
            "INSERT INTO user_app_access(user_id,app_id) VALUES ($1,$2)",
            vec![user.into(), app.into()],
        )
        .await;
        sql(&db,"INSERT INTO oauth_clients(id,app_id,identifier,secret_hash,type,redirect_uris,scopes,require_pkce) VALUES ($1,$2,$3,'test-hash','confidential',ARRAY['https://client.example.test/callback'],ARRAY['openid']::text[],false)",vec![client.into(),app.into(),client.to_string().into()]).await;
        sql(&db,"INSERT INTO identity_providers(id,code,name,kind,issuer) VALUES ($1,'local','Local','local','https://issuer.example.test')",vec![provider.into()]).await;
        let key_id = Uuid::now_v7();
        sql(&db,"INSERT INTO identity_provider_keys(id,provider_id,kid,public_key_pem,active) VALUES ($1,$2,'old',$3,true)",vec![key_id.into(),provider.into(),include_str!("../../../../../tests/fixtures/rsa-public.pem").into()]).await;
        crate::db::crypto_expr::update_signing_key_private_key(
            &db,
            include_str!("../../../../../tests/fixtures/rsa-private.pem"),
            key_id,
        )
        .await
        .unwrap();
        Self {
            fixture,
            guard,
            state,
            user,
            app,
            client,
            provider,
        }
    }
    async fn cleanup(self) {
        self.guard.shutdown().await;
        self.fixture.cleanup().await;
    }
}

fn refresh_form(client: Uuid, raw: &str) -> TokenRequest {
    TokenRequest {
        grant_type: "refresh_token".into(),
        code: None,
        redirect_uri: None,
        code_verifier: None,
        refresh_token: Some(raw.into()),
        scope: None,
        client_id: client.to_string(),
        client_secret: None,
    }
}

#[tokio::test]
#[ignore = "requires dedicated PERO_TEST_DATABASE_URL and PERO_TEST_REDIS_URL"]
async fn formatted_identifiers_keep_their_database_identity() {
    let fixture = SecurityFixture::new().await;
    let mut state = fixture.state.clone();
    let mut redis_config = state.config.redis.clone();
    redis_config.url = std::env::var("PERO_TEST_REDIS_URL")
        .unwrap()
        .parse()
        .unwrap();
    state.cache =
        std::sync::Arc::new(pero_cache_redis::RedisCacheStore::from_config(&redis_config).unwrap());
    let base = format!("9{}", uuid::Uuid::now_v7().as_u128());
    let formatted = format!("{base}-123");
    let compact = format!("{base}123");
    let other_user = Uuid::now_v7();
    sql(
        &state.db,
        "UPDATE users SET username=$2,phone=$2,phone_verified_at=now() WHERE id=$1",
        vec![fixture.user.into(), formatted.clone().into()],
    )
    .await;
    sql(
        &state.db,
        "INSERT INTO users(id,username,phone) VALUES($1,$2,$2)",
        vec![other_user.into(), compact.clone().into()],
    )
    .await;
    let hash = PasswordIdentityService::hash_password("OriginalPass123!")
        .await
        .unwrap();
    PasswordIdentityService::create_hashed(
        &state.db,
        fixture.user,
        fixture.provider,
        fixture.user.to_string(),
        hash,
        time::OffsetDateTime::now_utc(),
    )
    .await
    .unwrap();
    let login = crate::service::login::LoginService::new(&state.db, &state.cache);
    let result = login
        .password_login(
            &state.session_service(),
            None,
            "username",
            &formatted,
            "OriginalPass123!",
        )
        .await;
    let token = result.unwrap_or_else(|_| panic!("password login failed"));
    let session = state
        .session_service()
        .validate(&token)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(session.user_id, fixture.user);

    sql(
        &state.db,
        "UPDATE oauth_clients SET identifier=$2,type='public',secret_hash=NULL WHERE id=$1",
        vec![fixture.client.into(), formatted.clone().into()],
    )
    .await;
    let other_client = Uuid::now_v7();
    sql(&state.db, "INSERT INTO oauth_clients(id,app_id,identifier,type,redirect_uris) VALUES($1,$2,$3,'public',ARRAY['https://client.example.test/callback'])", vec![other_client.into(),fixture.app.into(),compact.into()]).await;
    let service = TokenService::new(&state);
    let mut form = refresh_form(fixture.client, "unused");
    form.client_id = formatted.clone();
    assert!(
        matches!(service.authenticate_client(&form).await, Ok(client) if client.id == fixture.client)
    );

    std::sync::Arc::make_mut(&mut state.config)
        .notification
        .endpoint = "https://gateway.example.test/send".into();
    let (jar, csrf_token) = state
        .web_security()
        .ensure_csrf(axum_extra::extract::CookieJar::new());
    let response = crate::web::sso::forgot_password::post_forgot(
        axum::extract::State(state.clone()),
        pero_api_axum::extractor::ClientIp(None),
        jar,
        axum::Form(crate::web::sso::dto::ForgotPasswordForm {
            csrf_token,
            identifier: formatted,
        }),
    )
    .await;
    assert_eq!(response.status(), http::StatusCode::OK);
    let tokens = crate::db::entity::password_reset_tokens::Entity::find()
        .all(&state.db)
        .await
        .unwrap();
    assert_eq!(tokens.len(), 1);
    assert_eq!(tokens[0].user_id, fixture.user);
    // Legal mailbox characters must not bypass recovery throttling.
    let email = format!("{base}{{a}}@example.test");
    sql(
        &state.db,
        "UPDATE users SET email=$2,email_verified_at=now() WHERE id=$1",
        vec![fixture.user.into(), email.clone().into()],
    )
    .await;
    let (jar, csrf) = state
        .web_security()
        .ensure_csrf(axum_extra::extract::CookieJar::new());
    for attempt in 0..4 {
        let response = crate::web::sso::forgot_password::post_forgot(
            axum::extract::State(state.clone()),
            pero_api_axum::extractor::ClientIp(None),
            jar.clone(),
            axum::Form(crate::web::sso::dto::ForgotPasswordForm {
                csrf_token: csrf.clone(),
                identifier: email.clone(),
            }),
        )
        .await;
        let body = axum::body::to_bytes(response.into_body(), 8192)
            .await
            .unwrap();
        let page: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(page["data"]["success"], attempt < 3);
        if attempt == 3 {
            assert_eq!(page["data"]["error"], "rate_limited");
        }
    }
    use sea_orm::PaginatorTrait;
    assert_eq!(
        crate::db::entity::password_reset_tokens::Entity::find()
            .count(&state.db)
            .await
            .unwrap(),
        4
    );
    // One source cannot bypass the budget by rotating recipient identifiers.
    let source = pero_api_axum::extractor::ClientIp(Some("192.0.2.33/32".parse().unwrap()));
    let source_key = pero_cache_redis::rate_limit_key::rl_reset_ip
        .key(&source.for_rate_limit())
        .unwrap();
    state.cache.set(source_key.clone(), &20_u64).await.unwrap();
    let response = crate::web::sso::forgot_password::post_forgot(
        axum::extract::State(state.clone()),
        source,
        jar,
        axum::Form(crate::web::sso::dto::ForgotPasswordForm {
            csrf_token: csrf,
            identifier: format!("new-{base}@example.test"),
        }),
    )
    .await;
    let body = axum::body::to_bytes(response.into_body(), 8192)
        .await
        .unwrap();
    let page: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(page["data"]["error"], "rate_limited");
    state.cache.del(source_key).await.unwrap();
    // Phone identifiers must match the stored contact.
    let normalized_phone = format!("{base}456");
    let formatted_phone = format!("{base}-456");
    sql(
        &state.db,
        "UPDATE users SET phone=$2 WHERE id=$1",
        vec![fixture.user.into(), normalized_phone.into()],
    )
    .await;
    let result = login
        .password_login(
            &state.session_service(),
            None,
            "phone",
            &formatted_phone,
            "OriginalPass123!",
        )
        .await;
    assert!(result.is_err());
    crate::service::recovery::request(&state, &formatted_phone)
        .await
        .unwrap();
    let tokens = crate::db::entity::password_reset_tokens::Entity::find()
        .all(&state.db)
        .await
        .unwrap();
    assert_eq!(tokens.len(), 4);
    assert!(tokens.iter().all(|token| token.user_id == fixture.user));
    let account = AccountService::new(&state);
    let registration = |username: &str| crate::service::account::RegisterUserParams {
        username: username.into(),
        email: None,
        phone: None,
        nickname: None,
        password: "OriginalPass123!".into(),
        auth_request_id: None,
    };
    assert!(
        account
            .register_user(registration(" trimmed_registration "))
            .await
            .is_ok()
    );
    let registered =
        crate::db::helper::user::find_by_identifier(&state.db, "username", "trimmed_registration")
            .await
            .unwrap()
            .unwrap();
    assert_eq!(registered.username, "trimmed_registration");
    assert!(matches!(
        account
            .register_user(registration("  trimmed_registration  "))
            .await,
        Err(crate::service::account::RegisterUserError::UsernameTaken)
    ));
    fixture.cleanup().await;
}

#[tokio::test]
#[ignore = "requires dedicated PERO_TEST_DATABASE_URL"]
async fn refresh_downscoping() {
    let fixture = SecurityFixture::new().await;
    let state = fixture.state.clone();
    let db = state.db.clone();
    let user = fixture.user;
    let app = fixture.app;
    let client = fixture.client;
    let service = TokenService::new(&state);
    // Invalid scope must not consume the refresh credential; downscoping affects only the AT.
    let (_, downscope_session) = state
        .session_service()
        .create(user, None, None, None, None)
        .await
        .unwrap();
    let downscope_raw = pero_utils::crypto::generate_token();
    sql(
        &db,
        "UPDATE oauth_clients SET scopes=ARRAY['openid','email']::text[] WHERE id=$1",
        vec![client.into()],
    )
    .await;
    let scoped_client = oauth_clients::Entity::find_by_id(client)
        .one(&db)
        .await
        .unwrap()
        .unwrap();
    sql(&db,"INSERT INTO refresh_tokens(token_hash,user_id,app_id,client_id,session_id,scopes,expires_at) VALUES($1,$2,$3,$4,$5,ARRAY['openid','email']::text[],now()+interval '1 day')",vec![pero_utils::crypto::sha256_hex(&downscope_raw).into(),user.into(),app.into(),client.into(),downscope_session.into()]).await;
    let mut request = refresh_form(client, &downscope_raw);
    request.scope = Some("admin".into());
    assert!(matches!(
        service.handle_refresh_token(&request, &scoped_client).await,
        TokenEndpointResult::Error {
            code: pero_error::protocol::oauth::OAuth2ErrorCode::InvalidScope,
            ..
        }
    ));
    request.scope = Some("openid".into());
    let TokenEndpointResult::Success(result) =
        service.handle_refresh_token(&request, &scoped_client).await
    else {
        panic!("downscoping failed")
    };
    assert_eq!(result.scope, "openid");
    let claims = pero_utils::oauth::jwt::verify_access_token(
        &result.access_token,
        "https://issuer.example.test",
        &client.to_string(),
        include_str!("../../../../../tests/fixtures/rsa-public.pem"),
    )
    .unwrap();
    assert_eq!(claims.scope, "openid");
    let TokenEndpointResult::Success(restored) = service
        .handle_refresh_token(
            &refresh_form(client, result.refresh_token.as_deref().unwrap()),
            &scoped_client,
        )
        .await
    else {
        panic!("replacement RT lost original grant")
    };
    assert_eq!(restored.scope, "openid email");
    sql(
        &db,
        "UPDATE oauth_clients SET scopes=ARRAY['openid']::text[] WHERE id=$1",
        vec![client.into()],
    )
    .await;

    fixture.cleanup().await;
}

#[tokio::test]
#[ignore = "requires dedicated PERO_TEST_DATABASE_URL"]
async fn refresh_replay() {
    let fixture = SecurityFixture::new().await;
    let state = fixture.state.clone();
    let db = state.db.clone();
    let user = fixture.user;
    let app = fixture.app;
    let client = fixture.client;
    let client_model = oauth_clients::Entity::find_by_id(fixture.client)
        .one(&db)
        .await
        .unwrap()
        .unwrap();
    let service = TokenService::new(&state);
    // A normal rotation succeeds; replay revokes the newly issued member of the family.
    let (_, session) = state
        .session_service()
        .create(user, None, None, None, None)
        .await
        .unwrap();
    let raw = pero_utils::crypto::generate_token();
    let rt = Uuid::now_v7();
    sql(&db,"INSERT INTO refresh_tokens(id,token_hash,user_id,app_id,client_id,session_id,scopes,expires_at) VALUES($1,$2,$3,$4,$5,$6,ARRAY['openid']::text[],now()+interval '1 day')",vec![rt.into(),pero_utils::crypto::sha256_hex(&raw).into(),user.into(),app.into(),client.into(),session.into()]).await;
    let result = service
        .handle_refresh_token(&refresh_form(client, &raw), &client_model)
        .await;
    assert!(
        matches!(result, TokenEndpointResult::Success(_)),
        "valid refresh must work"
    );
    // Revocation failures must be retryable, rather than claiming replay handling completed.
    db.execute_unprepared("CREATE FUNCTION fail_replay_revoke() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'simulated revocation failure'; END $$; CREATE TRIGGER fail_replay_revoke BEFORE UPDATE OF revoked_at ON sso_sessions FOR EACH ROW EXECUTE FUNCTION fail_replay_revoke()")
        .await.unwrap();
    assert!(matches!(
        service
            .handle_refresh_token(&refresh_form(client, &raw), &client_model)
            .await,
        TokenEndpointResult::Error {
            code: pero_error::protocol::oauth::OAuth2ErrorCode::TemporarilyUnavailable,
            ..
        }
    ));
    let row = refresh_tokens::Entity::find_by_id(rt)
        .one(&db)
        .await
        .unwrap()
        .unwrap();
    let replacement = refresh_tokens::Entity::find_by_id(row.replaced_by_id.unwrap())
        .one(&db)
        .await
        .unwrap()
        .unwrap();
    assert!(replacement.revoked_at.is_none());
    db.execute_unprepared(
        "DROP TRIGGER fail_replay_revoke ON sso_sessions; DROP FUNCTION fail_replay_revoke()",
    )
    .await
    .unwrap();
    // Retrying the same old token after recovery completes session-wide revocation.
    assert!(matches!(
        service
            .handle_refresh_token(&refresh_form(client, &raw), &client_model)
            .await,
        TokenEndpointResult::Error {
            code: pero_error::protocol::oauth::OAuth2ErrorCode::InvalidGrant,
            ..
        }
    ));
    let row = refresh_tokens::Entity::find_by_id(rt)
        .one(&db)
        .await
        .unwrap()
        .unwrap();
    let replacement = refresh_tokens::Entity::find_by_id(row.replaced_by_id.unwrap())
        .one(&db)
        .await
        .unwrap()
        .unwrap();
    assert!(replacement.revoked_at.is_some());

    fixture.cleanup().await;
}

#[tokio::test]
#[ignore = "requires dedicated PERO_TEST_DATABASE_URL"]
async fn refresh_concurrent_replay() {
    let fixture = SecurityFixture::new().await;
    let state = fixture.state.clone();
    let db = state.db.clone();
    let user = fixture.user;
    let app = fixture.app;
    let client = fixture.client;
    let client_model = oauth_clients::Entity::find_by_id(fixture.client)
        .one(&db)
        .await
        .unwrap()
        .unwrap();
    let service = TokenService::new(&state);
    // Concurrent uses of one RT have one winner; the replay revokes the whole family.
    let (_, session) = state
        .session_service()
        .create(user, None, None, None, None)
        .await
        .unwrap();
    let raw = pero_utils::crypto::generate_token();
    sql(&db,"INSERT INTO refresh_tokens(token_hash,user_id,app_id,client_id,session_id,scopes,expires_at) VALUES($1,$2,$3,$4,$5,ARRAY['openid']::text[],now()+interval '1 day')",vec![pero_utils::crypto::sha256_hex(&raw).into(),user.into(),app.into(),client.into(),session.into()]).await;
    let request = refresh_form(client, &raw);
    let (first, second) = tokio::join!(
        service.handle_refresh_token(&request, &client_model),
        service.handle_refresh_token(&request, &client_model)
    );
    assert_eq!(
        [first, second]
            .iter()
            .filter(|result| matches!(result, TokenEndpointResult::Success(_)))
            .count(),
        1
    );

    fixture.cleanup().await;
}

#[tokio::test]
#[ignore = "requires dedicated PERO_TEST_DATABASE_URL"]
async fn expired_sessions_deny_refresh() {
    let fixture = SecurityFixture::new().await;
    let state = fixture.state.clone();
    let db = state.db.clone();
    let user = fixture.user;
    let app = fixture.app;
    let client = fixture.client;
    let client_model = oauth_clients::Entity::find_by_id(fixture.client)
        .one(&db)
        .await
        .unwrap()
        .unwrap();
    let service = TokenService::new(&state);
    // Expiration, idle timeout and orphaning all deny refresh, including after cleanup.
    for kind in ["expired", "idle", "orphan"] {
        let (_, session) = state
            .session_service()
            .create(user, None, None, None, None)
            .await
            .unwrap();
        let raw = pero_utils::crypto::generate_token();
        let rt = Uuid::now_v7();
        sql(&db,"INSERT INTO refresh_tokens(id,token_hash,user_id,app_id,client_id,session_id,expires_at) VALUES($1,$2,$3,$4,$5,$6,now()+interval '1 day')",vec![rt.into(),pero_utils::crypto::sha256_hex(&raw).into(),user.into(),app.into(),client.into(),session.into()]).await;
        match kind {
            "expired" => sql(&db,"UPDATE sso_sessions SET created_at=now()-interval '2 hours',expires_at=now()-interval '1 hour' WHERE id=$1",vec![session.into()]).await,
            "idle" => sql(&db,"UPDATE sso_sessions SET last_seen_at=now()-interval '2 minutes' WHERE id=$1",vec![session.into()]).await,
            _ => sql(&db,"DELETE FROM sso_sessions WHERE id=$1",vec![session.into()]).await,
        }
        for after_cleanup in [false, true] {
            if after_cleanup {
                crate::db::helper::cleanup::clean_expired_sso_sessions(&db)
                    .await
                    .unwrap();
            }
            assert!(
                matches!(
                    service
                        .handle_refresh_token(&refresh_form(client, &raw), &client_model)
                        .await,
                    TokenEndpointResult::Error {
                        code: pero_error::protocol::oauth::OAuth2ErrorCode::InvalidGrant,
                        ..
                    }
                ),
                "{kind}, cleanup={after_cleanup}"
            );
        }
    }

    fixture.cleanup().await;
}

#[tokio::test]
#[ignore = "requires dedicated PERO_TEST_DATABASE_URL"]
async fn authorization_code_claims_and_scope() {
    let fixture = SecurityFixture::new().await;
    let state = fixture.state.clone();
    let db = state.db.clone();
    let user = fixture.user;
    let app = fixture.app;
    let client = fixture.client;
    let client_model = oauth_clients::Entity::find_by_id(fixture.client)
        .one(&db)
        .await
        .unwrap()
        .unwrap();
    let service = TokenService::new(&state);
    // A successful code exchange preserves the time of actual authentication in the ID token.
    let (_, authenticated_session) = state
        .session_service()
        .create(user, None, None, None, None)
        .await
        .unwrap();
    let authenticated_at = time::OffsetDateTime::now_utc().unix_timestamp() - 30;
    sql(
        &db,
        "UPDATE sso_sessions SET authenticated_at=to_timestamp($2) WHERE id=$1",
        vec![
            authenticated_session.into(),
            (authenticated_at as f64).into(),
        ],
    )
    .await;
    let successful_code = pero_utils::crypto::generate_token();
    let pkce = pero_utils::oauth::pkce::PkcePair::generate();
    sql(&db,"INSERT INTO authorization_codes(code_hash,user_id,app_id,client_id,session_id,redirect_uri,scopes,expires_at,code_challenge,code_challenge_method) VALUES($1,$2,$3,$4,$5,'https://client.example.test/callback',ARRAY['openid']::text[],now()+interval '5 minutes',$6,'S256')",vec![pero_utils::crypto::sha256_hex(&successful_code).into(),user.into(),app.into(),client.into(),authenticated_session.into(),pkce.code_challenge.into()]).await;
    let mut successful_form = TokenRequest {
        grant_type: "authorization_code".into(),
        code: Some(successful_code),
        redirect_uri: Some("https://client.example.test/callback".into()),
        code_verifier: Some(pkce.code_verifier.clone()),
        ..refresh_form(client, "")
    };
    let TokenEndpointResult::Success(tokens) = service
        .handle_authorization_code(&successful_form, &client_model)
        .await
    else {
        panic!("valid authorization code failed");
    };
    let claims = pero_utils::oauth::jwt::verify_id_token(
        tokens.id_token.as_ref().unwrap(),
        &state.config.oidc.issuer,
        &client_model.identifier,
        include_str!("../../../../../tests/fixtures/rsa-public.pem"),
    )
    .unwrap();
    assert_eq!(claims.auth_time, Some(authenticated_at));

    let mut headers = http::HeaderMap::new();
    headers.insert(
        "authorization",
        format!("Bearer {}", tokens.access_token).parse().unwrap(),
    );
    assert_eq!(
        crate::api::userinfo::userinfo(axum::extract::State(state.clone()), headers.clone())
            .await
            .status(),
        http::StatusCode::OK
    );
    successful_form.code_verifier = Some("wrong-proof".into());
    assert!(matches!(
        service
            .handle_authorization_code(&successful_form, &client_model)
            .await,
        TokenEndpointResult::Error {
            code: OAuth2ErrorCode::InvalidGrant,
            ..
        }
    ));
    assert_eq!(
        crate::api::userinfo::userinfo(axum::extract::State(state.clone()), headers.clone())
            .await
            .status(),
        http::StatusCode::OK
    );

    successful_form.code_verifier = Some(pkce.code_verifier);
    assert!(matches!(
        service
            .handle_authorization_code(&successful_form, &client_model)
            .await,
        TokenEndpointResult::Error {
            code: OAuth2ErrorCode::InvalidGrant,
            ..
        }
    ));
    assert_eq!(
        crate::api::userinfo::userinfo(axum::extract::State(state.clone()), headers)
            .await
            .status(),
        http::StatusCode::UNAUTHORIZED
    );
    assert!(matches!(
        service
            .handle_refresh_token(
                &refresh_form(client, tokens.refresh_token.as_ref().unwrap()),
                &client_model
            )
            .await,
        TokenEndpointResult::Error {
            code: OAuth2ErrorCode::InvalidGrant,
            ..
        }
    ));

    // Revoked scope cannot be recovered by redeeming a previously issued authorization code.
    let (_, session) = state
        .session_service()
        .create(user, None, None, None, None)
        .await
        .unwrap();
    let code = pero_utils::crypto::generate_token();
    sql(&db,"INSERT INTO authorization_codes(code_hash,user_id,app_id,client_id,session_id,redirect_uri,scopes,expires_at) VALUES($1,$2,$3,$4,$5,'https://client.example.test/callback',ARRAY['openid','email']::text[],now()+interval '5 minutes')",vec![pero_utils::crypto::sha256_hex(&code).into(),user.into(),app.into(),client.into(),session.into()]).await;
    let code_form = TokenRequest {
        grant_type: "authorization_code".into(),
        code: Some(code),
        redirect_uri: Some("https://client.example.test/callback".into()),
        ..refresh_form(client, "")
    };
    assert!(matches!(
        service
            .handle_authorization_code(&code_form, &client_model)
            .await,
        TokenEndpointResult::Error {
            code: pero_error::protocol::oauth::OAuth2ErrorCode::InvalidGrant,
            ..
        }
    ));

    fixture.cleanup().await;
}

#[tokio::test]
#[ignore = "requires dedicated PERO_TEST_DATABASE_URL"]
async fn recovery_and_contact_expiry() {
    let fixture = SecurityFixture::new().await;
    let mut state = fixture.state.clone();
    let db = state.db.clone();
    let user = fixture.user;
    let provider = fixture.provider;
    let config = std::sync::Arc::make_mut(&mut state.config);
    config.notification.endpoint = "https://notify.example.test".into();
    sql(
        &db,
        "UPDATE users SET email='recovery@example.test',phone='+15551234567' WHERE id=$1",
        vec![user.into()],
    )
    .await;
    // A social-only account must not receive a reset link that cannot be used.
    crate::service::recovery::request(&state, "recovery@example.test")
        .await
        .unwrap();
    use crate::db::entity::password_reset_tokens;
    use sea_orm::PaginatorTrait;
    assert_eq!(
        password_reset_tokens::Entity::find()
            .count(&db)
            .await
            .unwrap(),
        0
    );
    let notification_count = || async {
        db.query_one_raw(Statement::from_string(
            DbBackend::Postgres,
            "SELECT count(*) AS count FROM notification_outbox".to_owned(),
        ))
        .await
        .unwrap()
        .unwrap()
        .try_get::<i64>("", "count")
        .unwrap()
    };
    assert_eq!(notification_count().await, 0);
    // Outstanding recovery tokens are all consumed by a reset; a second token cannot restore access.
    let txn = db.begin().await.unwrap();
    let original_identity = PasswordIdentityService::create(
        &txn,
        user,
        provider,
        user.to_string(),
        "OldPassword123",
        time::OffsetDateTime::now_utc(),
    )
    .await
    .unwrap();
    txn.commit().await.unwrap();
    // Neither an unverified primary identifier nor an injected secondary identifier can recover the account.
    for identifier in ["recovery@example.test", "+15551234567"] {
        crate::service::recovery::request(&state, identifier)
            .await
            .unwrap();
    }
    assert_eq!(
        password_reset_tokens::Entity::find()
            .count(&db)
            .await
            .unwrap(),
        0
    );
    assert_eq!(notification_count().await, 0);
    sql(
        &db,
        "UPDATE users SET email_verified_at=now() WHERE id=$1",
        vec![user.into()],
    )
    .await;
    crate::service::recovery::request(&state, "recovery@example.test")
        .await
        .unwrap();
    assert_eq!(
        password_reset_tokens::Entity::find()
            .count(&db)
            .await
            .unwrap(),
        1
    );
    assert_eq!(notification_count().await, 1);

    let mut contacts = ContactVerificationService::new(&db, &state.cache);
    let (_, pending_nonce) = contacts
        .create_contact_request(
            user,
            ContactChannel::Phone,
            "+15557654321".into(),
            Some("https://issuer.example.test"),
        )
        .await
        .ok()
        .unwrap();
    assert_eq!(notification_count().await, 2);
    let mut resets = Vec::new();
    for _ in 0..2 {
        let token = pero_utils::oauth::jwt::sign_password_reset_token(
            &user.to_string(),
            3600,
            state.config.password_reset.signing_key.expose_secret(),
        )
        .unwrap();
        sql(&db,"INSERT INTO password_reset_tokens(user_id,token_hash,expires_at) VALUES($1,$2,now()+interval '1 hour')",vec![user.into(),pero_utils::crypto::sha256_hex(&token).into()]).await;
        resets.push(token);
    }
    let account = AccountService::new(&state);
    assert!(
        account
            .reset_password(&resets[0], "NewPassword123", "NewPassword123")
            .await
            .is_ok()
    );
    assert!(
        contacts
            .load_pending_request(&pending_nonce)
            .await
            .ok()
            .unwrap()
            .is_none()
    );
    assert_eq!(notification_count().await, 0);
    crate::service::recovery::request(&state, "+15551234567")
        .await
        .unwrap();
    assert_eq!(notification_count().await, 0);
    assert!(
        account
            .reset_password(&resets[1], "OtherPassword123", "OtherPassword123")
            .await
            .is_err()
    );

    assert!(
        state
            .session_service()
            .create_verified_password(&original_identity, None)
            .await
            .is_err(),
        "a verified but subsequently changed password cannot establish a new session"
    );
    let mut concurrent_resets = Vec::new();
    for _ in 0..2 {
        let token = pero_utils::oauth::jwt::sign_password_reset_token(
            &user.to_string(),
            3600,
            state.config.password_reset.signing_key.expose_secret(),
        )
        .unwrap();
        sql(&db,"INSERT INTO password_reset_tokens(user_id,token_hash,expires_at) VALUES($1,$2,now()+interval '1 hour')",vec![user.into(),pero_utils::crypto::sha256_hex(&token).into()]).await;
        concurrent_resets.push(token);
    }
    let (first, second) = tokio::join!(
        account.reset_password(
            &concurrent_resets[0],
            "ConcurrentOne123",
            "ConcurrentOne123"
        ),
        account.reset_password(
            &concurrent_resets[1],
            "ConcurrentTwo123",
            "ConcurrentTwo123"
        )
    );
    assert_eq!(
        [first.is_ok(), second.is_ok()]
            .into_iter()
            .filter(|value| *value)
            .count(),
        1
    );

    // An expired pending request does not occupy its target or prevent resending.
    let mut contacts = ContactVerificationService::new(&db, &state.cache);
    let (_, nonce) = contacts
        .create_contact_request(
            user,
            ContactChannel::Email,
            "first@example.test".into(),
            None,
        )
        .await
        .ok()
        .expect("first contact");
    sql(&db,"UPDATE contact_change_requests SET requested_at=now()-interval '30 minutes',expires_at=now()-interval '15 minutes' WHERE nonce=$1",vec![nonce.into()]).await;
    assert!(
        contacts
            .create_contact_request(
                user,
                ContactChannel::Email,
                "first@example.test".into(),
                None
            )
            .await
            .is_ok()
    );

    fixture.cleanup().await;
}

#[tokio::test]
#[ignore = "requires dedicated PERO_TEST_DATABASE_URL"]
async fn signing_key_rotation() {
    let fixture = SecurityFixture::new().await;
    let state = fixture.state.clone();
    let db = state.db.clone();
    let provider = fixture.provider;
    for kid in [".", ".."] {
        let result = crate::service::keys::create(
            &db,
            provider,
            crate::service::keys::KeyInput {
                kid: kid.into(),
                algorithm: crate::db::enums::KeyAlgorithm::Rs256,
                key_use: crate::db::enums::KeyUse::Sig,
                public_key_pem: include_str!("../../../../../tests/fixtures/rsa-public.pem").into(),
                private_key_pem: Some(
                    include_str!("../../../../../tests/fixtures/rsa-private.pem").into(),
                ),
                certificate_pem: None,
                not_before: None,
                expires_at: None,
                active: true,
            },
        )
        .await;
        assert!(matches!(
            result,
            Err(crate::service::ManagementError::Invalid("invalid_key_id"))
        ));
    }
    // Switching active keys preserves the old verification key and obeys the partial unique index.
    let new_key = Uuid::now_v7();
    sql(&db,"INSERT INTO identity_provider_keys(id,provider_id,kid,public_key_pem,active) VALUES ($1,$2,'new',$3,false)",vec![new_key.into(),provider.into(),include_str!("../../../../../tests/fixtures/rsa-public.pem").into()]).await;
    crate::db::crypto_expr::update_signing_key_private_key(
        &db,
        include_str!("../../../../../tests/fixtures/rsa-private.pem"),
        new_key,
    )
    .await
    .unwrap();
    let (jar, csrf_token) = state
        .web_security()
        .ensure_csrf(axum_extra::extract::CookieJar::new());
    let response = crate::web::dashboard::keys::activate(
        axum::extract::State(state.clone()),
        jar,
        axum::extract::Path((provider, "new".into())),
        axum::Form(crate::web::util::CsrfOnly { csrf_token }),
    )
    .await;
    let bytes = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    let response: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert!(response.get("error").is_none(), "{response}");
    assert_eq!(
        crate::db::helper::signing_key::require_active_signing_key(&db)
            .await
            .unwrap()
            .kid,
        "new"
    );
    assert!(
        crate::db::helper::signing_key::find_verification_key_by_kid(&db, "old")
            .await
            .unwrap()
            .is_some()
    );
    fixture.cleanup().await;
}

#[tokio::test]
#[ignore = "requires dedicated PERO_TEST_DATABASE_URL"]
async fn notification_retries_and_leases() {
    let fixture = SecurityFixture::new().await;
    let state = fixture.state.clone();
    let db = state.db.clone();
    let user = fixture.user;
    // Notification failures remain queued and retries carry the same idempotency key.
    let attempts = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let observed = attempts.clone();
    let started = std::sync::Arc::new(tokio::sync::Notify::new());
    let release = std::sync::Arc::new(tokio::sync::Notify::new());
    let handler_started = started.clone();
    let handler_release = release.clone();
    let gateway = axum::Router::new().route(
        "/send",
        axum::routing::post(
            move |headers: axum::http::HeaderMap,
                  axum::Json(body): axum::Json<serde_json::Value>| {
                let observed = observed.clone();
                let started = handler_started.clone();
                let release = handler_release.clone();
                async move {
                    assert_eq!(headers["authorization"], "Bearer test-gateway-secret");
                    assert_eq!(body["code"], "123456");
                    let first = {
                        let mut requests = observed.lock().unwrap();
                        requests.push(headers["idempotency-key"].to_str().unwrap().to_owned());
                        requests.len() == 1
                    };
                    if first {
                        started.notify_one();
                        release.notified().await;
                        axum::http::StatusCode::SERVICE_UNAVAILABLE
                    } else {
                        axum::http::StatusCode::ACCEPTED
                    }
                }
            },
        ),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}/send", listener.local_addr().unwrap());
    let gateway_task = tokio::spawn(async move { axum::serve(listener, gateway).await.unwrap() });
    let mut delivery_state = state.clone();
    let delivery_config = std::sync::Arc::make_mut(&mut delivery_state.config);
    delivery_config.notification.endpoint = endpoint;
    delivery_config.notification.bearer_token =
        pero_types::SecretString::new("test-gateway-secret");
    crate::service::notify::enqueue_verification(
        &db,
        user,
        "https://issuer.example.test",
        "email",
        "first@example.test",
        "123456",
        "test-nonce",
    )
    .await
    .unwrap();
    let worker_state = delivery_state.clone();
    let worker =
        tokio::spawn(async move { crate::service::notify::deliver_one(&worker_state).await });
    tokio::time::timeout(std::time::Duration::from_secs(5), started.notified())
        .await
        .unwrap();
    // No database row lock survives the HTTP request and another worker cannot take the live lease.
    let lock_probe = db.begin().await.unwrap();
    lock_probe
        .execute_unprepared("SELECT id FROM notification_outbox FOR UPDATE NOWAIT")
        .await
        .unwrap();
    lock_probe.rollback().await.unwrap();
    assert!(
        !crate::service::notify::deliver_one(&delivery_state)
            .await
            .unwrap()
    );
    release.notify_one();
    assert!(worker.await.unwrap().unwrap());
    let row = db
        .query_one_raw(Statement::from_string(
            DbBackend::Postgres,
            "SELECT attempts, payload_enc FROM notification_outbox".to_owned(),
        ))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.try_get::<i32>("", "attempts").unwrap(), 1);
    let ciphertext = row.try_get::<Vec<u8>>("", "payload_enc").unwrap();
    assert!(!ciphertext.windows(6).any(|value| value == b"123456"));
    sql(
        &db,
        "UPDATE notification_outbox SET next_attempt_at=now()",
        vec![],
    )
    .await;
    assert!(
        crate::service::notify::deliver_one(&delivery_state)
            .await
            .unwrap()
    );
    assert!(
        !crate::service::notify::deliver_one(&delivery_state)
            .await
            .unwrap()
    );
    {
        let requests = attempts.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0], requests[1]);
    }
    // A stalled delivery must not block another message in the same batch.
    attempts.lock().unwrap().clear();
    for nonce in ["parallel-first", "parallel-second"] {
        crate::service::notify::enqueue_verification(
            &db,
            user,
            "https://issuer.example.test",
            "email",
            "first@example.test",
            "123456",
            nonce,
        )
        .await
        .unwrap();
    }
    let worker_state = delivery_state.clone();
    let batch =
        tokio::spawn(async move { crate::service::notify::deliver_batch(&worker_state).await });
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        started.notified().await;
        loop {
            if attempts.lock().unwrap().len() == 2 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(!batch.is_finished());
    release.notify_one();
    tokio::time::timeout(std::time::Duration::from_secs(5), batch)
        .await
        .unwrap()
        .unwrap();
    {
        let requests = attempts.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert_ne!(requests[0], requests[1]);
    }
    gateway_task.abort();
    fixture.cleanup().await;
}

#[tokio::test]
#[ignore = "requires dedicated PERO_TEST_DATABASE_URL"]
async fn policy_revocation_locks() {
    let fixture = SecurityFixture::new().await;
    let state = fixture.state.clone();
    let db = state.db.clone();
    let user = fixture.user;
    let app = fixture.app;
    let client = fixture.client;
    // Policy locks make access revocation wait for in-flight issuance, then revoke its new RT too.
    let (_, fresh_session) = state
        .session_service()
        .create(user, None, None, None, None)
        .await
        .unwrap();
    let issuance = db.begin().await.unwrap();
    assert!(
        crate::service::access::lock_grant_access(&issuance, user, app)
            .await
            .unwrap()
            .is_some()
    );
    let (jar, csrf_token) = state
        .web_security()
        .ensure_csrf(axum_extra::extract::CookieJar::new());
    let revoke_state = state.clone();
    let mut revoke = tokio::spawn(async move {
        crate::web::dashboard::users::revoke_app(
            axum::extract::State(revoke_state),
            jar,
            axum::extract::Path(user),
            axum::Form(crate::web::dashboard::dto::RevokeAppForm {
                csrf_token,
                app_id: app.to_string(),
            }),
        )
        .await
    });
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(30), &mut revoke)
            .await
            .is_err()
    );
    let pending_rt = Uuid::now_v7();
    issuance.execute_raw(Statement::from_sql_and_values(DbBackend::Postgres,
        "INSERT INTO refresh_tokens(id,token_hash,user_id,app_id,client_id,session_id,expires_at) VALUES($1,$2,$3,$4,$5,$6,now()+interval '1 day')",
        vec![pending_rt.into(),pending_rt.to_string().into(),user.into(),app.into(),client.into(),fresh_session.into()])).await.unwrap();
    issuance.commit().await.unwrap();
    let revoked = tokio::time::timeout(std::time::Duration::from_secs(5), revoke)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(revoked.status(), axum::http::StatusCode::OK);
    assert!(
        refresh_tokens::Entity::find_by_id(pending_rt)
            .one(&db)
            .await
            .unwrap()
            .unwrap()
            .revoked_at
            .is_some()
    );
    // Concurrent grants use one upsert and never revive previously revoked tokens.
    let (first, second) = tokio::join!(
        crate::service::access::grant_app(&db, user, app),
        crate::service::access::grant_app(&db, user, app)
    );
    assert!(first.is_ok() && second.is_ok());
    assert!(
        crate::service::access::active_app_access(&db, user, app)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        refresh_tokens::Entity::find_by_id(pending_rt)
            .one(&db)
            .await
            .unwrap()
            .unwrap()
            .revoked_at
            .is_some()
    );
    fixture.cleanup().await;
}

#[tokio::test]
#[ignore = "requires dedicated PERO_TEST_DATABASE_URL"]
async fn session_touch_and_bounded_cleanup() {
    use crate::db::entity::sso_sessions;
    let fixture = SecurityFixture::new().await;
    let mut state = fixture.state.clone();
    let db = state.db.clone();
    let (raw, live) = state
        .session_service()
        .create(fixture.user, None, None, None, None)
        .await
        .unwrap();
    let before = sso_sessions::Entity::find_by_id(live)
        .one(&db)
        .await
        .unwrap()
        .unwrap()
        .last_seen_at;
    assert!(
        state
            .session_service()
            .validate(&raw)
            .await
            .unwrap()
            .is_some()
    );
    let touched = sso_sessions::Entity::find_by_id(live)
        .one(&db)
        .await
        .unwrap()
        .unwrap()
        .last_seen_at;
    assert!(
        touched > before,
        "default preserves per-request idle renewal"
    );
    let config = std::sync::Arc::make_mut(&mut state.config);
    config.sso.session_idle_ttl_seconds = 3600;
    config.sso.session_touch_interval_seconds = 30;
    for _ in 0..10 {
        assert!(
            state
                .session_service()
                .validate(&raw)
                .await
                .unwrap()
                .is_some()
        );
    }
    assert_eq!(
        sso_sessions::Entity::find_by_id(live)
            .one(&db)
            .await
            .unwrap()
            .unwrap()
            .last_seen_at,
        touched
    );
    sql(
        &db,
        "UPDATE sso_sessions SET last_seen_at=now()-interval '31 seconds' WHERE id=$1",
        vec![live.into()],
    )
    .await;
    assert!(
        state
            .session_service()
            .validate(&raw)
            .await
            .unwrap()
            .is_some()
    );
    assert!(
        sso_sessions::Entity::find_by_id(live)
            .one(&db)
            .await
            .unwrap()
            .unwrap()
            .last_seen_at
            > touched
    );
    // More than one batch, including grants which must be revoked before ON DELETE SET NULL.
    sql(&db, "INSERT INTO sso_sessions(token_hash,user_id,created_at,expires_at) SELECT 'expired-'||n,$1,now()-interval '2 days',now()-interval '1 day' FROM generate_series(1,1100) n", vec![fixture.user.into()]).await;
    sql(&db, "INSERT INTO refresh_tokens(token_hash,user_id,app_id,client_id,session_id,expires_at) SELECT token_hash,user_id,$1,$2,id,now()+interval '1 day' FROM sso_sessions", vec![fixture.app.into(),fixture.client.into()]).await;
    assert_eq!(
        crate::db::helper::cleanup::clean_expired_sso_sessions(&db)
            .await
            .unwrap(),
        1100
    );
    let row = db.query_one_raw(Statement::from_string(DbBackend::Postgres, "SELECT count(*) FILTER (WHERE revoked_at IS NOT NULL) AS revoked, count(*) FILTER (WHERE revoked_at IS NULL) AS live FROM refresh_tokens")).await.unwrap().unwrap();
    assert_eq!(row.try_get::<i64>("", "revoked").unwrap(), 1100);
    assert_eq!(row.try_get::<i64>("", "live").unwrap(), 1);
    assert!(
        state
            .session_service()
            .validate(&raw)
            .await
            .unwrap()
            .is_some()
    );
    sql(
        &db,
        "UPDATE sso_sessions SET revoked_at=now() WHERE id=$1",
        vec![live.into()],
    )
    .await;
    assert!(
        state
            .session_service()
            .validate(&raw)
            .await
            .unwrap()
            .is_none(),
        "touch batching never delays revocation"
    );
    fixture.cleanup().await;
}

#[tokio::test]
#[ignore = "requires dedicated PERO_TEST_DATABASE_URL"]
async fn stale_client_updates_cannot_overwrite_policy_or_revoke_grants() {
    use sea_orm::Set;
    let fixture = SecurityFixture::new().await;
    let db = &fixture.state.db;
    let original = oauth_clients::Entity::find_by_id(fixture.client)
        .one(db)
        .await
        .unwrap()
        .unwrap();
    let (_, session) = fixture
        .state
        .session_service()
        .create(fixture.user, None, None, None, None)
        .await
        .unwrap();
    let rt = Uuid::now_v7();
    sql(db,"INSERT INTO refresh_tokens(id,token_hash,user_id,app_id,client_id,session_id,expires_at) VALUES($1,$2,$3,$4,$5,$6,now()+interval '1 day')",vec![rt.into(),rt.to_string().into(),fixture.user.into(),fixture.app.into(),fixture.client.into(),session.into()]).await;
    sql(
        db,
        "UPDATE oauth_clients SET require_pkce=true WHERE id=$1",
        vec![fixture.client.into()],
    )
    .await;
    let mut stale: oauth_clients::ActiveModel = original.clone().into();
    stale.secret_hash = Set(Some("new-secret".into()));
    assert!(
        crate::service::client::save_security_change(db, &original, stale, Some("secret_rotated"))
            .await
            .is_err()
    );
    let current = oauth_clients::Entity::find_by_id(fixture.client)
        .one(db)
        .await
        .unwrap()
        .unwrap();
    assert!(current.require_pkce);
    assert_eq!(current.secret_hash, original.secret_hash);
    assert!(
        refresh_tokens::Entity::find_by_id(rt)
            .one(db)
            .await
            .unwrap()
            .unwrap()
            .revoked_at
            .is_none()
    );
    let mut changed: oauth_clients::ActiveModel = current.clone().into();
    changed.secret_hash = Set(Some("new-secret".into()));
    crate::service::client::save_security_change(db, &current, changed, Some("secret_rotated"))
        .await
        .unwrap();
    assert!(
        refresh_tokens::Entity::find_by_id(rt)
            .one(db)
            .await
            .unwrap()
            .unwrap()
            .revoked_at
            .is_some()
    );
    fixture.cleanup().await;
}

#[tokio::test]
#[ignore = "requires dedicated PERO_TEST_DATABASE_URL"]
async fn notification_cleanup_is_bounded_and_links_preserve_base_paths() {
    let fixture = SecurityFixture::new().await;
    let mut state = fixture.state.clone();
    let db = state.db.clone();
    sql(&db,"INSERT INTO notification_outbox (id,payload_enc,expires_at,user_id,kind) SELECT uuidv7(),''::bytea,now()-interval '1 second',$1,'verify_contact' FROM generate_series(1,1001)",vec![fixture.user.into()]).await;
    for remaining in [501i64, 1, 0] {
        assert!(!crate::service::notify::deliver_one(&state).await.unwrap());
        let row = db
            .query_one_raw(Statement::from_string(
                DbBackend::Postgres,
                "SELECT count(*) AS n FROM notification_outbox".to_owned(),
            ))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.try_get::<i64>("", "n").unwrap(), remaining);
    }
    let config = std::sync::Arc::make_mut(&mut state.config);
    config.sso.base_url = "https://issuer.example.test/tenant/".into();
    config.notification.endpoint = "https://gateway.example.test/send".into();
    sql(
        &db,
        "UPDATE users SET email='recovery@example.test',email_verified_at=now() WHERE id=$1",
        vec![fixture.user.into()],
    )
    .await;
    PasswordIdentityService::create(
        &db,
        fixture.user,
        fixture.provider,
        fixture.user.to_string(),
        "OriginalPass123!",
        time::OffsetDateTime::now_utc(),
    )
    .await
    .unwrap();
    crate::service::recovery::request(&state, "recovery@example.test")
        .await
        .unwrap();
    crate::service::notify::enqueue_verification(
        &db,
        fixture.user,
        &state.config.sso.base_url,
        "email",
        "recovery@example.test",
        "123456",
        "a&b+c",
    )
    .await
    .unwrap();
    let rows=db.query_all_raw(Statement::from_string(DbBackend::Postgres,"SELECT pgp_sym_decrypt(payload_enc,current_setting('app.encrypt_key')) AS payload FROM notification_outbox".to_owned())).await.unwrap();
    assert_eq!(rows.len(), 2);
    for row in rows {
        let payload: String = row.try_get("", "payload").unwrap();
        let payload: serde_json::Value = serde_json::from_str(&payload).unwrap();
        let link = url::Url::parse(payload["link"].as_str().unwrap()).unwrap();
        assert!(link.path().starts_with("/tenant/"));
        assert!(!link.path().contains("//"));
        if payload["kind"] == "verify_contact" {
            assert!(
                link.query_pairs()
                    .any(|(k, v)| k == "nonce" && v == "a&b+c")
            );
        } else {
            assert!(link.query_pairs().any(|(k, v)| {
                k == "token"
                    && pero_utils::oauth::jwt::verify_password_reset_token(
                        &v,
                        state.config.password_reset.signing_key.expose_secret(),
                    )
                    .is_ok()
            }));
        }
    }
    db.clone().close().await.unwrap();
    assert!(matches!(
        crate::service::recovery::request(&state, "recovery@example.test").await,
        Err(crate::service::recovery::RecoveryError::Dependency(_))
    ));
    fixture.cleanup().await;
}

#[tokio::test]
#[ignore = "requires dedicated PERO_TEST_DATABASE_URL"]
async fn management_mutations_serialize_and_revoke_atomically() {
    let fixture = SecurityFixture::new().await;
    let state = &fixture.state;
    let (a, b) = tokio::join!(
        crate::service::app::toggle_status(&state.db, fixture.app),
        crate::service::app::toggle_status(&state.db, fixture.app)
    );
    a.unwrap();
    b.unwrap();
    let app = crate::db::entity::apps::Entity::find_by_id(fixture.app)
        .one(&state.db)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(app.status, crate::db::enums::CommonStatus::Active);
    let (raw, _) = state
        .session_service()
        .create(fixture.user, None, None, None, None)
        .await
        .unwrap();
    let actor = Uuid::now_v7();
    assert!(matches!(
        crate::service::user::set_status(
            &state.db,
            fixture.user,
            fixture.user,
            crate::db::enums::UserStatus::Disabled
        )
        .await,
        Err(crate::service::ManagementError::Invalid(
            "cannot_modify_self"
        ))
    ));
    crate::service::user::set_status(
        &state.db,
        fixture.user,
        actor,
        crate::db::enums::UserStatus::Disabled,
    )
    .await
    .unwrap();
    assert!(
        state
            .session_service()
            .validate(&raw)
            .await
            .unwrap()
            .is_none()
    );
    sql(
        &state.db,
        "UPDATE apps SET system=true WHERE id=$1",
        vec![fixture.app.into()],
    )
    .await;
    assert!(matches!(
        crate::service::app::toggle_status(&state.db, fixture.app).await,
        Err(crate::service::ManagementError::Invalid(
            "system_app_protected"
        ))
    ));
    fixture.cleanup().await;
}

#[tokio::test]
#[ignore = "requires dedicated PERO_TEST_DATABASE_URL"]
async fn upstream_oidc_subject_nonce_and_configuration_cache_contract() {
    use crate::service::social::{SocialLoginError, TokenResult};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    struct Upstream {
        jwks_calls: Arc<AtomicUsize>,
        wrong_subject: Arc<AtomicUsize>,
    }
    #[async_trait::async_trait]
    impl pero_http_client_core::HttpClient for Upstream {
        async fn send(
            &self,
            request: http::Request<Vec<u8>>,
        ) -> pero_http_client_core::HttpClientResult<pero_http_client_core::HttpResponse> {
            let body = if request.uri().path() == "/jwks" {
                self.jwks_calls.fetch_add(1, Ordering::SeqCst);
                let jwk = pero_utils::oauth::jwk::rsa_public_key_to_jwk(
                    include_str!("../../../../../tests/fixtures/rsa-public.pem"),
                    "upstream",
                    "RS256",
                )
                .unwrap();
                serde_json::json!({"keys":[jwk]})
            } else {
                assert_eq!(request.headers()["authorization"], "Bearer upstream-access");
                serde_json::json!({"sub":if self.wrong_subject.load(Ordering::SeqCst)==1 {"wrong-user"} else {"upstream-user"},"email":"upstream@example.test","email_verified":true})
            };
            Ok(pero_http_client_core::HttpResponse {
                status: http::StatusCode::OK,
                headers: Default::default(),
                body: serde_json::to_vec(&body).unwrap(),
            })
        }
    }
    let fixture = SecurityFixture::new().await;
    let mut state = fixture.state.clone();
    let calls = Arc::new(AtomicUsize::new(0));
    let wrong = Arc::new(AtomicUsize::new(0));
    state.http_client = Arc::new(Upstream {
        jwks_calls: calls.clone(),
        wrong_subject: wrong.clone(),
    });
    Arc::make_mut(&mut state.config)
        .oauth2
        .upstream_jwks_cache_ttl_seconds = 60;
    let mut provider = crate::db::helper::provider::ProviderWithSecret {
        provider: crate::db::entity::identity_providers::Entity::find_by_id(fixture.provider)
            .one(&state.db)
            .await
            .unwrap()
            .unwrap(),
        client_secret: None,
    };
    provider.provider.kind = crate::db::enums::IdentityProviderKind::Oidc;
    provider.provider.issuer = Some("https://upstream.example.test".into());
    provider.provider.client_id = Some("upstream-client".into());
    provider.provider.jwks_uri = Some("https://upstream.example.test/jwks".into());
    provider.provider.userinfo_endpoint = Some("https://upstream.example.test/userinfo".into());
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let claims = serde_json::json!({"iss":"https://upstream.example.test","aud":"upstream-client","sub":"upstream-user","exp":now+600,"iat":now,"nonce":"current-flow","auth_time":now});
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some("upstream".into());
    let jwt = jsonwebtoken::encode(
        &header,
        &claims,
        &jsonwebtoken::EncodingKey::from_rsa_pem(include_bytes!(
            "../../../../../tests/fixtures/rsa-private.pem"
        ))
        .unwrap(),
    )
    .unwrap();
    let token = TokenResult {
        access_token: "upstream-access".into(),
        raw: serde_json::json!({"id_token":jwt}),
    };
    for _ in 0..2 {
        let info = state
            .social_service()
            .fetch_userinfo(&provider, &token, Some("current-flow"), Some(now))
            .await
            .ok()
            .unwrap();
        assert_eq!(info.sub, "upstream-user");
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    provider.provider.updated_at += time::Duration::seconds(1);
    assert!(
        state
            .social_service()
            .fetch_userinfo(&provider, &token, Some("current-flow"), Some(now))
            .await
            .is_ok()
    );
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert!(matches!(
        state
            .social_service()
            .fetch_userinfo(&provider, &token, Some("replayed-flow"), None)
            .await,
        Err(SocialLoginError::TokenExchangeFailed(_))
    ));
    wrong.store(1, Ordering::SeqCst);
    assert!(matches!(
        state
            .social_service()
            .fetch_userinfo(&provider, &token, Some("current-flow"), None)
            .await,
        Err(SocialLoginError::UserinfoFailed(_))
    ));
    fixture.cleanup().await;
}

#[tokio::test]
#[ignore = "requires dedicated PERO_TEST_DATABASE_URL"]
async fn consent_submissions_bind_to_the_displayed_request_and_session() {
    use crate::web::{
        security::AuthReqCookieValue,
        sso::{consent, dto::ConsentForm},
    };
    use axum_extra::extract::cookie::{Cookie, CookieJar};
    let fixture = SecurityFixture::new().await;
    let state = &fixture.state;
    let client_b = Uuid::now_v7();
    sql(&state.db,"INSERT INTO oauth_clients(id,app_id,identifier,type,redirect_uris,scopes) VALUES($1,$2,$3,'public',ARRAY['https://client.example.test/callback'],ARRAY['openid'])",vec![client_b.into(),fixture.app.into(),client_b.to_string().into()]).await;
    let (raw, sid) = state
        .session_service()
        .create(fixture.user, None, None, None, None)
        .await
        .unwrap();
    let (jar, csrf_token) = state
        .web_security()
        .ensure_csrf(CookieJar::new().add(Cookie::new("pero_sso", raw)));
    let request_cookie = state.cookie_factory().auth_req_cookie_name();
    let mut requests = Vec::new();
    for client in [fixture.client, client_b] {
        let id = Uuid::now_v7();
        sql(&state.db,"INSERT INTO authorization_requests(id,client_id,app_id,redirect_uri,scopes,expires_at) VALUES($1,$2,$3,'https://client.example.test/callback',ARRAY['openid'],now()+interval '5 minutes')",vec![id.into(),client.into(),fixture.app.into()]).await;
        let token = state
            .cookie_factory()
            .encode_auth_request(&AuthReqCookieValue {
                auth_request_id: id,
                user_id: fixture.user,
                session_id: sid,
            })
            .unwrap();
        let page = consent::get(
            axum::extract::State(state.clone()),
            jar.clone()
                .add(Cookie::new(request_cookie.clone(), token.clone())),
        )
        .await;
        let data: serde_json::Value =
            serde_json::from_slice(&axum::body::to_bytes(page.into_body(), 65536).await.unwrap())
                .unwrap();
        assert_eq!(data["data"]["request_token"], token);
        requests.push((id, token));
    }
    // The second tab has replaced the shared cookie, but the first tab still submits A.
    let jar = jar.add(Cookie::new(request_cookie.clone(), requests[1].1.clone()));
    let (other_raw, _) = state
        .session_service()
        .create(fixture.user, None, None, None, None)
        .await
        .unwrap();
    let other_jar = CookieJar::new().add(Cookie::new("pero_sso", other_raw));
    let (other_jar, other_csrf) = state.web_security().ensure_csrf(other_jar);
    let rejected = consent::post(
        axum::extract::State(state.clone()),
        other_jar,
        axum::Form(ConsentForm {
            action: "allow".into(),
            csrf_token: other_csrf,
            request_token: requests[0].1.clone(),
        }),
    )
    .await;
    assert_eq!(
        rejected.headers()["location"],
        "/sso/error?code=invalid_request"
    );
    let response = consent::post(
        axum::extract::State(state.clone()),
        jar.clone(),
        axum::Form(ConsentForm {
            action: "allow".into(),
            csrf_token: csrf_token.clone(),
            request_token: requests[0].1.clone(),
        }),
    )
    .await;
    assert!(
        response.headers()["location"]
            .to_str()
            .unwrap()
            .contains("code=")
    );
    let expected_cookie = format!("{request_cookie}={}", requests[1].1);
    assert!(
        response
            .headers()
            .get_all("set-cookie")
            .iter()
            .all(|value| {
                let value = value.to_str().unwrap();
                !value.starts_with(&format!("{request_cookie}="))
                    || value.split(';').next() == Some(expected_cookie.as_str())
            })
    );
    let codes = crate::db::entity::authorization_codes::Entity::find()
        .all(&state.db)
        .await
        .unwrap();
    assert_eq!(codes.len(), 1);
    assert_eq!(codes[0].client_id, fixture.client);
    // A failed consent deletion must roll back the terminal request state.
    state.db.execute_unprepared("CREATE FUNCTION fail_consent_delete() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected consent deletion failure'; END $$; CREATE TRIGGER fail_consent_delete BEFORE DELETE ON user_consents FOR EACH STATEMENT EXECUTE FUNCTION fail_consent_delete()")
        .await.unwrap();
    let unavailable = consent::post(
        axum::extract::State(state.clone()),
        jar.clone(),
        axum::Form(ConsentForm {
            action: "deny".into(),
            csrf_token: csrf_token.clone(),
            request_token: requests[1].1.clone(),
        }),
    )
    .await;
    assert_eq!(
        unavailable.status(),
        axum::http::StatusCode::SERVICE_UNAVAILABLE
    );
    state.db.execute_unprepared("DROP TRIGGER fail_consent_delete ON user_consents; DROP FUNCTION fail_consent_delete()")
        .await.unwrap();
    assert!(
        crate::db::entity::authorization_requests::Entity::find_by_id(requests[1].0)
            .one(&state.db)
            .await
            .unwrap()
            .unwrap()
            .completed_at
            .is_none()
    );
    let response = consent::post(
        axum::extract::State(state.clone()),
        jar,
        axum::Form(ConsentForm {
            action: "deny".into(),
            csrf_token,
            request_token: requests[1].1.clone(),
        }),
    )
    .await;
    assert!(
        response.headers()["location"]
            .to_str()
            .unwrap()
            .contains("error=access_denied")
    );
    let grants = crate::db::entity::user_consents::Entity::find()
        .all(&state.db)
        .await
        .unwrap();
    assert_eq!(grants.len(), 1);
    assert_eq!(grants[0].client_id, fixture.client);
    fixture.cleanup().await;
}

#[tokio::test]
#[ignore = "requires dedicated PERO_TEST_DATABASE_URL"]
async fn concurrent_first_consents_both_issue_codes() {
    let fixture = SecurityFixture::new().await;
    let (_, session_id) = fixture
        .state
        .session_service()
        .create(fixture.user, None, None, None, None)
        .await
        .unwrap();
    let now = time::OffsetDateTime::now_utc();
    let session = crate::state::session::SsoSession {
        id: session_id,
        user_id: fixture.user,
        identity_id: None,
        created_at: now,
        authenticated_at: now,
    };
    let mut requests = Vec::new();
    for _ in 0..2 {
        let id = Uuid::now_v7();
        sql(&fixture.state.db, "INSERT INTO authorization_requests(id,client_id,app_id,redirect_uri,scopes,expires_at) VALUES($1,$2,$3,'https://client.example.test/callback',ARRAY['openid'],now()+interval '5 minutes')", vec![id.into(),fixture.client.into(),fixture.app.into()]).await;
        requests.push(id);
    }
    let oauth = fixture.state.oauth_service();
    let (first, second) = tokio::join!(
        oauth.issue_auth_code_with_consent(requests[0], &session, true),
        oauth.issue_auth_code_with_consent(requests[1], &session, true),
    );
    assert!(first.is_ok());
    assert!(second.is_ok());
    assert_ne!(first.unwrap(), second.unwrap());
    let grants = crate::db::entity::user_consents::Entity::find()
        .all(&fixture.state.db)
        .await
        .unwrap();
    assert_eq!(grants.len(), 1);
    // A denial that already passed the HTTP precheck must not overwrite a
    // completion committed while its UPDATE was waiting for the request lock.
    use axum_extra::extract::cookie::{Cookie, CookieJar};
    let request = Uuid::now_v7();
    sql(&fixture.state.db, "INSERT INTO authorization_requests(id,client_id,app_id,redirect_uri,scopes,expires_at) VALUES($1,$2,$3,'https://client.example.test/callback',ARRAY['openid'],now()+interval '5 minutes')", vec![request.into(),fixture.client.into(),fixture.app.into()]).await;
    let (raw, _) = fixture
        .state
        .session_service()
        .create(fixture.user, None, None, None, None)
        .await
        .unwrap();
    let session = fixture
        .state
        .session_service()
        .validate(&raw)
        .await
        .unwrap()
        .unwrap();
    let request_token = fixture
        .state
        .cookie_factory()
        .encode_auth_request(&crate::web::security::AuthReqCookieValue {
            auth_request_id: request,
            user_id: fixture.user,
            session_id: session.id,
        })
        .unwrap();
    let (jar, csrf_token) = fixture
        .state
        .web_security()
        .ensure_csrf(CookieJar::new().add(Cookie::new("pero_sso", raw)));
    let txn = fixture.state.db.begin().await.unwrap();
    txn.execute_raw(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "SELECT id FROM authorization_requests WHERE id=$1 FOR UPDATE",
        [request.into()],
    ))
    .await
    .unwrap();
    let blocker: i32 = txn
        .query_one_raw(Statement::from_string(
            DbBackend::Postgres,
            "SELECT pg_backend_pid() AS pid".to_owned(),
        ))
        .await
        .unwrap()
        .unwrap()
        .try_get("", "pid")
        .unwrap();
    let state = fixture.state.clone();
    let denial = tokio::spawn(async move {
        crate::web::sso::consent::post(
            axum::extract::State(state),
            jar,
            axum::Form(crate::web::sso::dto::ConsentForm {
                action: "deny".into(),
                csrf_token,
                request_token,
            }),
        )
        .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let blocked: bool = fixture.state.db.query_one_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid))) AS blocked",
                [blocker.into()])).await.unwrap().unwrap().try_get("", "blocked").unwrap();
            if blocked { break; }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }).await.expect("denial reached the request write after its precheck");
    txn.execute_raw(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "UPDATE authorization_requests SET completed_at=now(),authorized_user_id=$2 WHERE id=$1",
        [request.into(), fixture.user.into()],
    ))
    .await
    .unwrap();
    txn.commit().await.unwrap();
    let response = denial.await.unwrap();
    assert_eq!(
        response.headers()["location"],
        "/sso/error?code=invalid_request"
    );
    assert!(
        crate::db::entity::user_consents::Entity::find_by_id((fixture.user, fixture.client))
            .one(&fixture.state.db)
            .await
            .unwrap()
            .is_some()
    );
    fixture.cleanup().await;
}

#[tokio::test]
#[ignore = "requires dedicated PERO_TEST_DATABASE_URL"]
async fn client_revocation_precedes_authorization_request_locks() {
    let fixture = SecurityFixture::new().await;
    let (raw, _) = fixture
        .state
        .session_service()
        .create(fixture.user, None, None, None, None)
        .await
        .unwrap();
    let session = fixture
        .state
        .session_service()
        .validate(&raw)
        .await
        .unwrap()
        .unwrap();
    let request = Uuid::now_v7();
    sql(&fixture.state.db, "INSERT INTO authorization_requests(id,client_id,app_id,redirect_uri,scopes,expires_at) VALUES($1,$2,$3,'https://client.example.test/callback',ARRAY['openid'],now()+interval '5 minutes')", vec![request.into(),fixture.client.into(),fixture.app.into()]).await;
    let txn = fixture.state.db.begin().await.unwrap();
    txn.execute_raw(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "SELECT id FROM oauth_clients WHERE id=$1 FOR UPDATE",
        [fixture.client.into()],
    ))
    .await
    .unwrap();
    let pid: i32 = txn
        .query_one_raw(Statement::from_string(
            DbBackend::Postgres,
            "SELECT pg_backend_pid() AS pid".to_owned(),
        ))
        .await
        .unwrap()
        .unwrap()
        .try_get("", "pid")
        .unwrap();
    let state = fixture.state.clone();
    let issuance = tokio::spawn(async move {
        state
            .oauth_service()
            .issue_auth_code_with_consent(request, &session, true)
            .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let blocked: bool = fixture.state.db.query_one_raw(Statement::from_sql_and_values(DbBackend::Postgres,
                "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid))) AS blocked", [pid.into()])).await.unwrap().unwrap().try_get("", "blocked").unwrap();
            if blocked { break; }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }).await.expect("issuance must wait on the client policy lock");
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        crate::service::session::SessionService::revoke_client_grants(
            &txn,
            fixture.client,
            "test_revocation",
        ),
    )
    .await
    .expect("revocation must not deadlock on the request")
    .unwrap();
    txn.commit().await.unwrap();
    assert!(issuance.await.unwrap().is_err());
    fixture.cleanup().await;
}

#[tokio::test]
#[ignore = "requires dedicated PERO_TEST_DATABASE_URL"]
async fn access_tokens_stay_revoked_after_policy_restoration() {
    let fixture = SecurityFixture::new().await;
    let state = &fixture.state;
    let (raw_session, session) = state
        .session_service()
        .create(fixture.user, None, None, None, None)
        .await
        .unwrap();
    let issue = async |client_id: Uuid| {
        let client = oauth_clients::Entity::find_by_id(client_id)
            .one(&state.db)
            .await
            .unwrap()
            .unwrap();
        let code = pero_utils::crypto::generate_token();
        sql(&state.db, "INSERT INTO authorization_codes(code_hash,user_id,app_id,client_id,session_id,redirect_uri,scopes,expires_at) VALUES($1,$2,$3,$4,$5,'https://client.example.test/callback',ARRAY['openid']::text[],now()+interval '5 minutes')", vec![pero_utils::crypto::sha256_hex(&code).into(),fixture.user.into(),fixture.app.into(),client_id.into(),session.into()]).await;
        let form = TokenRequest {
            grant_type: "authorization_code".into(),
            code: Some(code),
            redirect_uri: Some("https://client.example.test/callback".into()),
            ..refresh_form(client_id, "")
        };
        let TokenEndpointResult::Success(tokens) = TokenService::new(state)
            .handle_authorization_code(&form, &client)
            .await
        else {
            panic!("valid code exchange failed");
        };
        tokens
    };
    let status = async |token: &str| {
        let mut headers = http::HeaderMap::new();
        headers.insert("authorization", format!("Bearer {token}").parse().unwrap());
        crate::api::userinfo::userinfo(axum::extract::State(state.clone()), headers)
            .await
            .status()
    };
    let original = issue(fixture.client).await;
    assert_eq!(status(&original.access_token).await, http::StatusCode::OK);
    crate::service::access::revoke_app(&state.db, fixture.user, fixture.app)
        .await
        .unwrap();
    crate::service::access::grant_app(&state.db, fixture.user, fixture.app)
        .await
        .unwrap();
    assert_eq!(
        status(&original.access_token).await,
        http::StatusCode::UNAUTHORIZED
    );

    let regranted = issue(fixture.client).await;
    assert_eq!(status(&regranted.access_token).await, http::StatusCode::OK);
    let sibling = Uuid::now_v7();
    sql(&state.db, "INSERT INTO oauth_clients(id,app_id,identifier,secret_hash,redirect_uris,scopes,require_pkce) VALUES($1,$2,$3,'test-hash',ARRAY['https://client.example.test/callback'],ARRAY['openid']::text[],false)", vec![sibling.into(),fixture.app.into(),sibling.to_string().into()]).await;
    let sibling_tokens = issue(sibling).await;
    crate::service::client::reset_secret(&state.db, fixture.client)
        .await
        .unwrap();
    assert_eq!(
        status(&regranted.access_token).await,
        http::StatusCode::UNAUTHORIZED
    );

    assert_eq!(
        status(&sibling_tokens.access_token).await,
        http::StatusCode::OK
    );

    let rotated = issue(fixture.client).await;
    assert_eq!(status(&rotated.access_token).await, http::StatusCode::OK);
    // Refresh issuance also binds the current versions, without revoking its previous AT.
    let client = oauth_clients::Entity::find_by_id(fixture.client)
        .one(&state.db)
        .await
        .unwrap()
        .unwrap();
    let TokenEndpointResult::Success(refreshed) = TokenService::new(state)
        .handle_refresh_token(
            &refresh_form(fixture.client, rotated.refresh_token.as_ref().unwrap()),
            &client,
        )
        .await
    else {
        panic!("valid refresh failed");
    };
    assert_eq!(status(&refreshed.access_token).await, http::StatusCode::OK);
    assert_eq!(status(&rotated.access_token).await, http::StatusCode::OK);
    crate::service::client::toggle_status(&state.db, fixture.client)
        .await
        .unwrap();
    crate::service::client::toggle_status(&state.db, fixture.client)
        .await
        .unwrap();
    assert_eq!(
        status(&refreshed.access_token).await,
        http::StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        status(&rotated.access_token).await,
        http::StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        status(&original.access_token).await,
        http::StatusCode::UNAUTHORIZED
    );

    // Application disablement must persist its revocation after re-enabling too.
    let enabled = issue(fixture.client).await;
    crate::service::app::toggle_status(&state.db, fixture.app)
        .await
        .unwrap();
    crate::service::app::toggle_status(&state.db, fixture.app)
        .await
        .unwrap();
    assert_eq!(
        status(&enabled.access_token).await,
        http::StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        status(&sibling_tokens.access_token).await,
        http::StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        status(&issue(fixture.client).await.access_token).await,
        http::StatusCode::OK
    );
    assert!(
        state
            .session_service()
            .validate(&raw_session)
            .await
            .unwrap()
            .is_some()
    );
    fixture.cleanup().await;
}
