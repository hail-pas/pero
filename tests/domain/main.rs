#[path = "../common/mod.rs"]
mod common;

use async_trait::async_trait;
use pero::domain::abac::engine::evaluate;
use pero::domain::abac::models::{EvalContext, Policy, PolicyCondition, RouteScope};
use pero::domain::abac::resource::{Action, Resource};
use pero::domain::app::models::{App, CreateAppRequest, UpdateAppRequest};
use pero::domain::app::repo::AppStore;
use pero::domain::app::service::{create_app, delete_app, get_app, list_apps, update_app};
use pero::domain::auth::session::{build_refresh_token, hash_refresh_token, parse_session_id};
use pero::domain::oauth::claims::ScopedClaims;
use pero::domain::oauth::entity::OAuth2Client;
use pero::domain::oauth::error::OAuth2Error;
use pero::domain::oauth::models::{
    CreateClientRequest, GrantType, RevokeRequest, TokenRequest, UpdateClientRequest,
};
use pero::domain::oauth::pkce::verify_pkce;
use pero::domain::oauth::repo::{AuthorizationCodeStore, CreateAuthCodeParams, OAuth2ClientStore, RefreshTokenStore};
use pero::domain::oauth::service::{
    ensure_authorization_client_ready, ensure_client_grant_allowed, ensure_redirect_uri_allowed,
    parse_basic_client_auth_header, resolve_client_credentials,
};
use pero::domain::oauth::{authorize as oauth_authorize, token_builder::build_token_response};
use pero::domain::user::entity::User;
use pero::domain::user::repo::UserStore;
use pero::shared::constants::oauth2::scopes;
use pero::shared::constants::oauth2::{
    GRANT_TYPE_AUTH_CODE, GRANT_TYPE_REFRESH_TOKEN, PKCE_METHOD_S256,
};
use pero::shared::error::AppError;
use pero::shared::patch::{FieldUpdate, Patch};
use pero::shared::{utils, validation};
use sha2::Digest;
use std::collections::HashMap;
use std::sync::Mutex;
use uuid::Uuid;
use validator::Validate;
use validator::ValidationErrors;

fn user_with_claims() -> User {
    User {
        id: Uuid::new_v4(),
        username: "alice".into(),
        email: Some("alice@example.test".into()),
        phone: Some("+12025550123".into()),
        nickname: Some("Alice".into()),
        avatar_url: Some("https://cdn.example.test/a.png".into()),
        email_verified: true,
        phone_verified: false,
        status: 1,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

fn policy(effect: &str, app_id: Option<Uuid>, priority: i32) -> Policy {
    let now = chrono::Utc::now();
    Policy {
        id: Uuid::new_v4(),
        name: format!("{effect}-{priority}"),
        description: None,
        effect: effect.into(),
        priority,
        enabled: true,
        app_id,
        created_at: now,
        updated_at: now,
    }
}

fn condition(condition_type: &str, key: &str, operator: &str, value: &str) -> PolicyCondition {
    PolicyCondition {
        id: Uuid::new_v4(),
        policy_id: Uuid::new_v4(),
        condition_type: condition_type.into(),
        key: key.into(),
        operator: operator.into(),
        value: value.into(),
    }
}

fn oauth_client(enabled: bool) -> OAuth2Client {
    let now = chrono::Utc::now();
    OAuth2Client {
        id: Uuid::new_v4(),
        app_id: Uuid::new_v4(),
        client_id: "client".into(),
        client_secret_hash: pero::shared::crypto::hash_secret("secret").unwrap(),
        client_name: "Client".into(),
        redirect_uris: vec!["https://app.example.test/callback".into()],
        grant_types: vec![
            GRANT_TYPE_AUTH_CODE.to_string(),
            GRANT_TYPE_REFRESH_TOKEN.to_string(),
        ],
        scopes: vec![scopes::OPENID.into(), scopes::EMAIL.into()],
        post_logout_redirect_uris: vec![],
        enabled,
        created_at: now,
        updated_at: now,
    }
}

fn pkce_challenge(verifier: &str) -> String {
    base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        sha2::Digest::finalize(sha2::Sha256::new_with_prefix(verifier.as_bytes())),
    )
}

#[derive(Default)]
struct DomainAppStore {
    apps: Mutex<HashMap<Uuid, App>>,
}

impl DomainAppStore {
    fn app(id: Uuid, code: &str, enabled: bool) -> App {
        let now = chrono::Utc::now();
        App {
            id,
            name: format!("{code} app"),
            code: code.into(),
            description: Some("test app".into()),
            enabled,
            created_at: now,
            updated_at: now,
        }
    }

    fn insert(&self, app: App) {
        self.apps.lock().unwrap().insert(app.id, app);
    }
}

#[async_trait]
impl AppStore for DomainAppStore {
    async fn create(&self, req: &CreateAppRequest) -> Result<App, AppError> {
        let app = Self::app(Uuid::new_v4(), &req.code, true);
        self.insert(app.clone());
        Ok(app)
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<App>, AppError> {
        Ok(self.apps.lock().unwrap().get(&id).cloned())
    }

    async fn find_by_code(&self, code: &str) -> Result<Option<App>, AppError> {
        Ok(self
            .apps
            .lock()
            .unwrap()
            .values()
            .find(|app| app.code == code)
            .cloned())
    }

    async fn list(&self, page: i64, page_size: i64) -> Result<(Vec<App>, i64), AppError> {
        let apps: Vec<_> = self.apps.lock().unwrap().values().cloned().collect();
        let total = apps.len() as i64;
        let start = ((page.max(1) - 1) * page_size.max(1)) as usize;
        let end = (start + page_size.max(1) as usize).min(apps.len());
        Ok((apps.get(start..end).unwrap_or(&[]).to_vec(), total))
    }

    async fn update(&self, id: Uuid, req: &UpdateAppRequest) -> Result<App, AppError> {
        let mut apps = self.apps.lock().unwrap();
        let app = apps
            .get_mut(&id)
            .ok_or_else(|| AppError::NotFound("app".into()))?;
        if let FieldUpdate::Set(name) = &req.name {
            app.name = name.clone();
        }
        if let FieldUpdate::Set(description) = &req.description {
            app.description = Some(description.clone());
        }
        if matches!(req.description, FieldUpdate::Clear) {
            app.description = None;
        }
        if let FieldUpdate::Set(enabled) = req.enabled {
            app.enabled = enabled;
        }
        Ok(app.clone())
    }

    async fn delete(&self, id: Uuid) -> Result<(), AppError> {
        self.apps.lock().unwrap().remove(&id);
        Ok(())
    }
}

#[test]
fn auth_refresh_tokens_parse_and_hash_without_exposing_secret() {
    let token = build_refresh_token("session-1");

    assert_eq!(parse_session_id(&token).unwrap(), "session-1");
    assert_ne!(hash_refresh_token(&token), token);
    assert!(parse_session_id("invalid").is_err());
}

#[test]
fn oauth_pkce_accepts_s256_and_rejects_unknown_method() {
    let verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~123456";
    let challenge = base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        sha2::Digest::finalize(sha2::Sha256::new_with_prefix(verifier.as_bytes())),
    );

    assert!(verify_pkce(verifier, &challenge, PKCE_METHOD_S256));
    assert!(!verify_pkce(verifier, &challenge, "plain"));
}

#[test]
fn scoped_claims_respect_requested_scopes() {
    let user = user_with_claims();
    let claims = ScopedClaims::from_user_and_scopes(
        &user,
        &[scopes::PROFILE.to_string(), scopes::EMAIL.to_string()],
    );

    assert_eq!(claims.name.as_deref(), Some("Alice"));
    assert_eq!(claims.email.as_deref(), Some("alice@example.test"));
    assert_eq!(claims.phone_number, None);
}

#[test]
fn oauth_errors_map_to_protocol_codes_and_statuses() {
    assert_eq!(OAuth2Error::InvalidClient.error_code(), "invalid_client");
    assert_eq!(OAuth2Error::InvalidClient.http_status(), 401);
    assert!(OAuth2Error::InvalidClient.needs_www_authenticate());
    assert_eq!(
        OAuth2Error::RefreshTokenReplay.error_code(),
        "invalid_grant"
    );
}

#[test]
fn patch_and_field_update_validate_required_null_values() {
    let mut patch_errors = ValidationErrors::new();
    Patch::<String>::Null.validate_required("name", &mut patch_errors, |_| Ok(()));
    assert!(patch_errors.field_errors().contains_key("name"));

    let mut field_errors = ValidationErrors::new();
    FieldUpdate::<String>::Clear.reject_clear("email", &mut field_errors, |_| Ok(()));
    assert!(field_errors.field_errors().contains_key("email"));
}

#[test]
fn abac_evaluator_matches_subject_resource_action_app_and_deny_precedence() {
    let app_id = Uuid::new_v4();
    let mut subject_attrs = HashMap::new();
    subject_attrs.insert("role".into(), vec!["admin".into(), "auditor".into()]);
    subject_attrs.insert("level".into(), vec!["9".into()]);
    let ctx = EvalContext {
        subject_attrs,
        resource: "/api/users/123".into(),
        action: "GET".into(),
        domain_resource: Some(Resource::User),
        domain_action: Some(Action::Read),
        app_id: Some(app_id),
        route_scope: RouteScope::App,
    };

    let allow = (
        policy("allow", Some(app_id), 10),
        vec![
            condition("subject", "role", "in", "admin,owner"),
            condition("subject", "level", "gt", "5"),
            condition("resource", "path", "wildcard", "/api/users/*"),
            condition("resource", "type", "eq", "user"),
            condition("action", "type", "eq", "read"),
            condition("app", "app_id", "eq", &app_id.to_string()),
        ],
    );
    let deny = (
        policy("deny", Some(app_id), 20),
        vec![condition("resource", "path", "regex", r"^/api/users/\d+$")],
    );

    assert_eq!(evaluate(&[allow, deny], &ctx, "deny"), "deny");
}

#[test]
fn abac_evaluator_respects_scope_compatibility_and_default_action() {
    let app_id = Uuid::new_v4();
    let ctx = EvalContext {
        subject_attrs: HashMap::new(),
        resource: "/admin".into(),
        action: "POST".into(),
        domain_resource: None,
        domain_action: None,
        app_id: None,
        route_scope: RouteScope::Admin,
    };
    let app_scoped = (
        policy("allow", Some(app_id), 1),
        vec![condition("resource", "path", "eq", "/admin")],
    );
    let empty_conditions = (policy("allow", None, 2), vec![]);

    assert_eq!(
        evaluate(&[app_scoped, empty_conditions], &ctx, "deny"),
        "deny"
    );
}

#[tokio::test]
async fn app_service_creates_lists_updates_gets_and_deletes_apps() {
    let store = DomainAppStore::default();
    let req = CreateAppRequest {
        name: "Admin".into(),
        code: "admin".into(),
        description: Some("Admin app".into()),
    };

    let created = create_app(&store, &req).await.unwrap();
    assert_eq!(created.code, "admin");
    assert!(create_app(&store, &req).await.is_err());

    let page = list_apps(&store, 1, 10).await.unwrap();
    assert_eq!(page.total, 1);

    let updated = update_app(
        &store,
        created.id,
        &UpdateAppRequest {
            name: FieldUpdate::Set("Admin Console".into()),
            description: FieldUpdate::Clear,
            enabled: FieldUpdate::Set(false),
        },
    )
    .await
    .unwrap();
    assert_eq!(updated.name, "Admin Console");
    assert!(!updated.enabled);
    assert_eq!(updated.description, None);

    assert_eq!(get_app(&store, created.id).await.unwrap().id, created.id);
    assert_eq!(
        delete_app(&store, created.id).await.unwrap().message,
        "app deleted"
    );
    assert!(get_app(&store, created.id).await.is_err());
}

#[test]
fn oauth_client_validation_and_basic_credentials_cover_success_and_errors() {
    let client = oauth_client(true);

    assert!(ensure_redirect_uri_allowed(&client, "https://app.example.test/callback").is_ok());
    assert!(ensure_redirect_uri_allowed(&client, "https://evil.example.test/callback").is_err());
    assert!(ensure_client_grant_allowed(&client, GRANT_TYPE_AUTH_CODE).is_ok());
    assert!(ensure_client_grant_allowed(&client, "client_credentials").is_err());
    assert!(
        ensure_authorization_client_ready(&client, &[scopes::OPENID.into(), scopes::EMAIL.into()])
            .is_ok()
    );
    assert!(ensure_authorization_client_ready(&client, &[scopes::PHONE.into()]).is_err());
    assert!(ensure_authorization_client_ready(&oauth_client(false), &[]).is_err());

    let encoded = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        "client%20id:secret%2Bvalue",
    );
    let (client_id, secret) = parse_basic_client_auth_header(&format!("Basic {encoded}")).unwrap();
    assert_eq!(client_id, "client id");
    assert_eq!(secret, "secret+value");
    assert!(parse_basic_client_auth_header("Bearer token").is_err());
}

#[test]
fn oauth_resolve_client_credentials_rejects_duplicates_and_sets_missing_values() {
    let encoded =
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, "client:secret");
    let req = TokenRequest {
        grant_type: GrantType::AuthorizationCode,
        code: Some("code".into()),
        redirect_uri: Some("https://app.example.test/callback".into()),
        client_id: None,
        client_secret: None,
        code_verifier: Some("a".repeat(43)),
        refresh_token: None,
    };
    let req = resolve_client_credentials(Some(&format!("Basic {encoded}")), req).unwrap();
    assert_eq!(req.client_id.as_deref(), Some("client"));
    assert_eq!(req.client_secret.as_deref(), Some("secret"));

    let duplicate = RevokeRequest {
        token: "token".into(),
        token_type_hint: None,
        client_id: Some("client".into()),
        client_secret: None,
    };
    assert!(resolve_client_credentials(Some(&format!("Basic {encoded}")), duplicate).is_err());
}

#[test]
fn oauth_token_builder_includes_id_token_only_for_openid_scope() {
    let signer = common::NoopStore;
    let client = oauth_client(true);
    let user = user_with_claims();
    let with_openid = build_token_response(
        &signer,
        5,
        "https://auth.example.test",
        &client,
        &user,
        &[scopes::OPENID.into(), scopes::EMAIL.into()],
        123,
        Some("nonce".into()),
        Some("sid".into()),
        Some("refresh".into()),
    )
    .unwrap();
    assert_eq!(with_openid.access_token, format!("access:{}", user.id));
    assert_eq!(with_openid.id_token, Some(format!("id:{}", user.id)));
    assert_eq!(with_openid.refresh_token.as_deref(), Some("refresh"));

    let without_openid = build_token_response(
        &signer,
        5,
        "https://auth.example.test",
        &client,
        &user,
        &[scopes::EMAIL.into()],
        123,
        None,
        None,
        None,
    )
    .unwrap();
    assert_eq!(without_openid.id_token, None);
}

#[test]
fn dto_validation_rejects_bad_app_and_oauth_updates() {
    assert!(
        CreateAppRequest {
            name: "Bad".into(),
            code: "Bad Code".into(),
            description: None,
        }
        .validate()
        .is_err()
    );

    assert!(
        UpdateClientRequest {
            client_name: FieldUpdate::Clear,
            redirect_uris: FieldUpdate::Set(vec!["not-a-url".into()]),
            grant_types: FieldUpdate::Set(vec!["password".into()]),
            scopes: FieldUpdate::Set(vec!["unknown".into()]),
            post_logout_redirect_uris: FieldUpdate::Set(vec!["not-a-url".into()]),
            enabled: FieldUpdate::Clear,
        }
        .validate()
        .is_err()
    );
}

#[test]
fn resource_and_action_classify_routes_and_methods() {
    assert_eq!(Resource::from_path("/api/users/1").as_str(), "user");
    assert_eq!(Resource::from_path("/api/apps").as_str(), "app");
    assert_eq!(
        Resource::from_path("/api/oauth2/clients").as_str(),
        "oauth2_client"
    );
    assert_eq!(
        Resource::from_path("/api/social-providers").as_str(),
        "social_provider"
    );
    assert_eq!(Resource::from_path("/oauth2/userinfo").as_str(), "userinfo");
    assert_eq!(
        Resource::from_path("/api/abac/evaluate").as_str(),
        "evaluate"
    );
    assert_eq!(Resource::from_path("/custom/path").as_str(), "/custom/path");

    assert_eq!(
        Action::from_method_and_path("GET", "/api/users").as_str(),
        "list"
    );
    assert_eq!(
        Action::from_method_and_path("GET", "/api/users/123/profile").as_str(),
        "read"
    );
    assert_eq!(
        Action::from_method_and_path("POST", "/api/users/1/policies/2/assign").as_str(),
        "assign"
    );
    assert_eq!(
        Action::from_method_and_path("DELETE", "/api/users/1/policies/2").as_str(),
        "unassign"
    );
    assert_eq!(
        Action::from_method_and_path("PATCH", "/x").as_str(),
        "PATCH"
    );
}

#[test]
fn shared_validation_accepts_good_inputs_and_rejects_bad_inputs() {
    assert!(validation::validate_url("https://example.test/path").is_ok());
    assert!(validation::validate_url("not a url").is_err());
    assert!(
        validation::validate_redirect_uris(&[
            "https://app.example.test/callback".into(),
            "http://localhost:3000/callback".into(),
        ])
        .is_ok()
    );
    assert!(validation::validate_redirect_uri("javascript:alert(1)").is_err());
    assert!(validation::validate_pkce_verifier(&"a".repeat(43)).is_ok());
    assert!(validation::validate_pkce_verifier("bad space").is_err());
    assert!(validation::validate_pkce_challenge(&"b".repeat(43)).is_ok());
    assert!(validation::validate_non_empty_items(&["openid".into()]).is_ok());
    assert!(validation::validate_non_empty_items(&["".into()]).is_err());
}

#[test]
fn shared_utils_normalize_empty_strings_and_append_query_params() {
    #[derive(serde::Deserialize)]
    struct Form {
        #[serde(deserialize_with = "utils::empty_string_as_none")]
        value: Option<String>,
    }

    let empty: Form = serde_json::from_value(serde_json::json!({ "value": "" })).unwrap();
    let present: Form = serde_json::from_value(serde_json::json!({ "value": "x" })).unwrap();
    assert_eq!(empty.value, None);
    assert_eq!(present.value.as_deref(), Some("x"));

    let url = utils::append_query_params(
        "https://example.test/callback?existing=1",
        &[("state", "a b"), ("code", "c+d")],
    )
    .unwrap();
    assert!(url.contains("existing=1"));
    assert!(url.contains("state=a+b"));
    assert!(url.contains("code=c%2Bd"));
    assert_eq!(
        utils::parse_scopes(Some("openid  email profile")),
        vec!["openid", "email", "profile"]
    );
    assert_eq!(
        utils::safe_local_path("%2Faccount").as_deref(),
        Some("/account")
    );
    assert_eq!(utils::safe_local_path("//evil.example.test"), None);
}

#[test]
fn oauth_create_client_request_defaults_and_validation_cover_allowed_sets() {
    let req: CreateClientRequest = serde_json::from_value(serde_json::json!({
        "app_id": Uuid::new_v4(),
        "client_name": "Client",
        "redirect_uris": ["https://app.example.test/callback"]
    }))
    .unwrap();
    assert!(req.validate().is_ok());
    assert_eq!(req.grant_types, vec![GRANT_TYPE_AUTH_CODE.to_string()]);
    assert!(req.scopes.contains(&scopes::OPENID.to_string()));

    let invalid: CreateClientRequest = serde_json::from_value(serde_json::json!({
        "app_id": Uuid::new_v4(),
        "client_name": "Client",
        "redirect_uris": ["https://app.example.test/callback"],
        "grant_types": ["refresh_token"],
        "scopes": ["openid", "unknown"]
    }))
    .unwrap();
    assert!(invalid.validate().is_err());
}

#[tokio::test]
async fn oauth_authorize_module_validates_clients_and_scopes() {
    let apps = common::MemoryAppStore::default();
    let clients = common::MemoryOAuth2ClientStore::default();
    let app = apps
        .create(&CreateAppRequest {
            name: "OAuth App".into(),
            code: "oauth_app".into(),
            description: None,
        })
        .await
        .unwrap();
    let client = clients
        .create(
            "authorize-client",
            &pero::shared::crypto::hash_secret("secret").unwrap(),
            &CreateClientRequest {
                app_id: app.id,
                client_name: "Authorize Client".into(),
                redirect_uris: vec!["https://app.example.test/callback".into()],
                grant_types: vec![GRANT_TYPE_AUTH_CODE.into(), GRANT_TYPE_REFRESH_TOKEN.into()],
                scopes: vec![scopes::OPENID.into(), scopes::EMAIL.into()],
                post_logout_redirect_uris: vec![],
            },
        )
        .await
        .unwrap();

    let valid = oauth_authorize::validate_authorization_client(
        &clients,
        &apps,
        &client.client_id,
        "https://app.example.test/callback",
        &[scopes::OPENID.into()],
    )
    .await
    .unwrap();
    assert_eq!(valid.id, client.id);

    assert!(
        oauth_authorize::validate_authorization_client(
            &clients,
            &apps,
            &client.client_id,
            "https://app.example.test/other",
            &[scopes::OPENID.into()],
        )
        .await
        .is_err()
    );
    assert!(
        oauth_authorize::validate_authorization_client(
            &clients,
            &apps,
            &client.client_id,
            "https://app.example.test/callback",
            &[scopes::PHONE.into()],
        )
        .await
        .is_err()
    );
}

#[tokio::test]
async fn oauth_token_exchange_authorization_code_success_and_pkce_failure() {
    let apps = common::MemoryAppStore::default();
    let clients = common::MemoryOAuth2ClientStore::default();
    let tokens = common::MemoryOAuthTokenStore::default();
    let users = common::MemoryIdentityStore::default();
    let app = apps
        .create(&CreateAppRequest {
            name: "Token App".into(),
            code: "token_app".into(),
            description: None,
        })
        .await
        .unwrap();
    let client = clients
        .create(
            "token-client",
            &pero::shared::crypto::hash_secret("secret").unwrap(),
            &CreateClientRequest {
                app_id: app.id,
                client_name: "Token Client".into(),
                redirect_uris: vec!["https://app.example.test/callback".into()],
                grant_types: vec![GRANT_TYPE_AUTH_CODE.into(), GRANT_TYPE_REFRESH_TOKEN.into()],
                scopes: vec![scopes::OPENID.into(), scopes::EMAIL.into()],
                post_logout_redirect_uris: vec![],
            },
        )
        .await
        .unwrap();
    let user = users
        .create_with_password(
            "token_user",
            Some("token@example.test"),
            None,
            None,
            &pero::shared::crypto::hash_secret("password123").unwrap(),
        )
        .await
        .unwrap();
    let verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~123456";
    let code = "auth-code-1";
    tokens
        .create_auth_code(CreateAuthCodeParams {
            code: code.into(),
            client_id: client.id,
            user_id: user.id,
            redirect_uri: "https://app.example.test/callback".into(),
            scopes: vec![scopes::OPENID.into(), scopes::EMAIL.into()],
            code_challenge: pkce_challenge(verifier),
            code_challenge_method: PKCE_METHOD_S256.into(),
            nonce: Some("nonce".into()),
            sid: Some("sid".into()),
            auth_time: 123,
            ttl_minutes: 5,
        })
        .await
        .unwrap();

    let response = pero::domain::oauth::token_exchange::exchange_token(
        &clients,
        &tokens,
        &tokens,
        &apps,
        &users,
        &common::NoopStore,
        5,
        1,
        "https://auth.example.test",
        &TokenRequest {
            grant_type: GrantType::AuthorizationCode,
            code: Some(code.into()),
            redirect_uri: Some("https://app.example.test/callback".into()),
            client_id: Some(client.client_id.clone()),
            client_secret: Some("secret".into()),
            code_verifier: Some(verifier.into()),
            refresh_token: None,
        },
    )
    .await
    .unwrap();
    assert_eq!(response.access_token, format!("access:{}", user.id));
    assert!(response.id_token.is_some());
    assert!(response.refresh_token.is_some());

    tokens
        .create_auth_code(CreateAuthCodeParams {
            code: "auth-code-2".into(),
            client_id: client.id,
            user_id: user.id,
            redirect_uri: "https://app.example.test/callback".into(),
            scopes: vec![scopes::OPENID.into()],
            code_challenge: pkce_challenge(verifier),
            code_challenge_method: PKCE_METHOD_S256.into(),
            nonce: None,
            sid: None,
            auth_time: 123,
            ttl_minutes: 5,
        })
        .await
        .unwrap();
    assert!(
        pero::domain::oauth::token_exchange::exchange_token(
            &clients,
            &tokens,
            &tokens,
            &apps,
            &users,
            &common::NoopStore,
            5,
            1,
            "https://auth.example.test",
            &TokenRequest {
                grant_type: GrantType::AuthorizationCode,
                code: Some("auth-code-2".into()),
                redirect_uri: Some("https://app.example.test/callback".into()),
                client_id: Some(client.client_id.clone()),
                client_secret: Some("secret".into()),
                code_verifier: Some("wrong-verifier".into()),
                refresh_token: None,
            },
        )
        .await
        .is_err()
    );
}

#[tokio::test]
async fn oauth_token_exchange_rotates_refresh_and_revokes_family_on_replay() {
    let apps = common::MemoryAppStore::default();
    let clients = common::MemoryOAuth2ClientStore::default();
    let tokens = common::MemoryOAuthTokenStore::default();
    let users = common::MemoryIdentityStore::default();
    let app = apps
        .create(&CreateAppRequest {
            name: "Refresh App".into(),
            code: "refresh_app".into(),
            description: None,
        })
        .await
        .unwrap();
    let client = clients
        .create(
            "refresh-client",
            &pero::shared::crypto::hash_secret("secret").unwrap(),
            &CreateClientRequest {
                app_id: app.id,
                client_name: "Refresh Client".into(),
                redirect_uris: vec!["https://app.example.test/callback".into()],
                grant_types: vec![GRANT_TYPE_AUTH_CODE.into(), GRANT_TYPE_REFRESH_TOKEN.into()],
                scopes: vec![scopes::OPENID.into()],
                post_logout_redirect_uris: vec![],
            },
        )
        .await
        .unwrap();
    let user = users
        .create_with_password(
            "refresh_user",
            None,
            None,
            None,
            &pero::shared::crypto::hash_secret("password123").unwrap(),
        )
        .await
        .unwrap();
    let family_id = Uuid::new_v4();
    tokens
        .create_refresh_token(
            client.id,
            user.id,
            "old-refresh",
            &[scopes::OPENID.into()],
            123,
            1,
            Some(family_id),
        )
        .await
        .unwrap();

    let rotated = pero::domain::oauth::token_exchange::exchange_token(
        &clients,
        &tokens,
        &tokens,
        &apps,
        &users,
        &common::NoopStore,
        5,
        1,
        "https://auth.example.test",
        &TokenRequest {
            grant_type: GrantType::RefreshToken,
            code: None,
            redirect_uri: None,
            client_id: Some(client.client_id.clone()),
            client_secret: Some("secret".into()),
            code_verifier: None,
            refresh_token: Some("old-refresh".into()),
        },
    )
    .await
    .unwrap();
    let new_refresh = rotated.refresh_token.unwrap();
    assert_ne!(new_refresh, "old-refresh");

    assert!(
        pero::domain::oauth::token_exchange::exchange_token(
            &clients,
            &tokens,
            &tokens,
            &apps,
            &users,
            &common::NoopStore,
            5,
            1,
            "https://auth.example.test",
            &TokenRequest {
                grant_type: GrantType::RefreshToken,
                code: None,
                redirect_uri: None,
                client_id: Some(client.client_id),
                client_secret: Some("secret".into()),
                code_verifier: None,
                refresh_token: Some("old-refresh".into()),
            },
        )
        .await
        .is_err()
    );
    assert_eq!(tokens.revoked_family_count(), 1);
}
