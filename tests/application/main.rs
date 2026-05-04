#[path = "../common/mod.rs"]
mod common;

use async_trait::async_trait;
use common::{
    MemoryAbacStore, MemoryAppStore, MemoryIdentityStore, MemoryOAuth2ClientStore,
    MemoryOAuthTokenStore, MemorySessionStore, MemorySsoStore,
};
use pero::application::{password_reset, social_login, sso_login, token_exchange};
use pero::domain::app::models::CreateAppRequest;
use pero::domain::app::repo::AppStore;
use pero::domain::auth::repo::SessionStore;
use pero::domain::auth::service::AuthService;
use pero::domain::credential::repo::IdentityStore;
use pero::domain::federation::entity::{
    CreateSocialProviderRequest, SocialProvider, UpdateSocialProviderRequest,
};
use pero::domain::federation::http::HttpClient;
use pero::domain::federation::repo::SocialStore;
use pero::domain::federation::service::{SocialBindState, SocialState};
use pero::domain::oauth::models::{GrantType, RevokeRequest, TokenRequest};
use pero::domain::oauth::repo::OAuth2ClientStore;
use pero::domain::sso::models::{AuthorizeParams, LoginForm, RegisterForm, SsoSession};
use pero::domain::sso::repo::SsoSessionStore;
use pero::domain::user::models::{
    AttributeItem, IdentifierType, RegisterRequest, SetAttributes, UpdateMeRequest,
    UpdateUserRequest,
};
use pero::domain::user::repo::{UserAttributeStore, UserStore};
use pero::shared::cache_keys::social::state_key;
use pero::shared::error::AppError;
use pero::shared::kv::KvStore;
use pero::shared::patch::FieldUpdate;
use serde_json::{Value, json};
use std::sync::Mutex;
use uuid::Uuid;

fn sso_session() -> SsoSession {
    SsoSession {
        authorize_params: AuthorizeParams {
            client_id: "client".into(),
            redirect_uri: "https://app.test/callback".into(),
            response_type: "code".into(),
            scope: Some("openid profile".into()),
            state: None,
            code_challenge: "x".repeat(43),
            code_challenge_method: "S256".into(),
            nonce: None,
        },
        user_id: None,
        authenticated: false,
        auth_time: None,
    }
}

fn social_provider(enabled: bool) -> SocialProvider {
    let now = chrono::Utc::now();
    SocialProvider {
        id: Uuid::new_v4(),
        name: "google".into(),
        display_name: "Google".into(),
        client_id: "client".into(),
        client_secret: "secret".into(),
        authorize_url: "https://accounts.example.test/auth".into(),
        token_url: "https://accounts.example.test/token".into(),
        userinfo_url: "https://accounts.example.test/userinfo".into(),
        scopes: vec!["openid".into(), "email".into()],
        enabled,
        created_at: now,
        updated_at: now,
    }
}

struct TestSocialStore {
    provider: Mutex<SocialProvider>,
}

impl Default for TestSocialStore {
    fn default() -> Self {
        Self {
            provider: Mutex::new(social_provider(true)),
        }
    }
}

#[async_trait]
impl SocialStore for TestSocialStore {
    async fn create_provider(
        &self,
        _req: &CreateSocialProviderRequest,
    ) -> Result<SocialProvider, AppError> {
        Ok(self.provider.lock().unwrap().clone())
    }

    async fn find_provider_by_name(&self, name: &str) -> Result<Option<SocialProvider>, AppError> {
        let provider = self.provider.lock().unwrap().clone();
        Ok((provider.name == name).then_some(provider))
    }

    async fn find_provider_by_id(&self, id: Uuid) -> Result<Option<SocialProvider>, AppError> {
        let provider = self.provider.lock().unwrap().clone();
        Ok((provider.id == id).then_some(provider))
    }

    async fn find_enabled_provider_by_name(
        &self,
        name: &str,
    ) -> Result<Option<SocialProvider>, AppError> {
        let provider = self.provider.lock().unwrap().clone();
        Ok((provider.name == name && provider.enabled).then_some(provider))
    }

    async fn list_enabled_providers(&self) -> Result<Vec<SocialProvider>, AppError> {
        let provider = self.provider.lock().unwrap().clone();
        Ok(if provider.enabled {
            vec![provider]
        } else {
            vec![]
        })
    }

    async fn list_all_providers(&self) -> Result<Vec<SocialProvider>, AppError> {
        Ok(vec![self.provider.lock().unwrap().clone()])
    }

    async fn update_provider(
        &self,
        _id: Uuid,
        _req: &UpdateSocialProviderRequest,
    ) -> Result<SocialProvider, AppError> {
        Ok(self.provider.lock().unwrap().clone())
    }

    async fn delete_provider(&self, _id: Uuid) -> Result<(), AppError> {
        Ok(())
    }
}

#[derive(Default)]
struct TestHttpClient;

#[async_trait]
impl HttpClient for TestHttpClient {
    async fn post_form(&self, _url: &str, fields: Vec<(&str, &str)>) -> Result<Value, AppError> {
        assert!(
            fields
                .iter()
                .any(|(key, value)| *key == "code" && *value == "oauth-code")
        );
        Ok(json!({ "access_token": "access-token" }))
    }

    async fn get_bearer(&self, _url: &str, access_token: &str) -> Result<Value, AppError> {
        assert_eq!(access_token, "access-token");
        Ok(json!({
            "sub": "google-user-1",
            "email": "social@example.test",
            "email_verified": true,
            "name": "Social User",
            "picture": "https://cdn.example.test/avatar.png"
        }))
    }
}

#[tokio::test]
async fn sso_register_authenticates_session_in_memory_backend() {
    let users = MemoryIdentityStore::default();
    let sso_sessions = MemorySsoStore::default();
    let mut sso = sso_session();
    let sid = sso_sessions.create(&sso, 60).await.unwrap();
    let form = RegisterForm {
        username: "app_reg".into(),
        email: Some("app_reg@example.test".into()),
        password: "password123".into(),
        phone: None,
        nickname: Some("App".into()),
    };

    let user = sso_login::register_and_authenticate(
        &users,
        &users,
        &sso_sessions,
        &sid,
        &mut sso,
        &form,
        60,
    )
    .await
    .unwrap();

    let stored = sso_sessions.get(&sid).await.unwrap().unwrap();
    assert_eq!(stored.user_id, Some(user.id));
    assert!(stored.authenticated);
}

#[tokio::test]
async fn sso_login_rejects_wrong_password_without_mutating_session() {
    let users = MemoryIdentityStore::default();
    let sso_sessions = MemorySsoStore::default();
    let _ = users
        .create_with_password(
            "login_user",
            None,
            None,
            None,
            &pero::shared::crypto::hash_secret("password123").unwrap(),
        )
        .await
        .unwrap();
    let mut sso = sso_session();
    let sid = sso_sessions.create(&sso, 60).await.unwrap();
    let form = LoginForm {
        identifier: "login_user".into(),
        identifier_type: IdentifierType::Username,
        password: "wrongpassword".into(),
    };

    let result =
        sso_login::login_and_authenticate(&users, &users, &sso_sessions, &sid, &mut sso, &form, 60)
            .await;

    assert!(matches!(result, Err(AppError::Unauthorized)));
    assert!(!sso_sessions.get(&sid).await.unwrap().unwrap().authenticated);
}

#[tokio::test]
async fn password_reset_updates_credential_and_revokes_sessions_and_tokens() {
    let users = MemoryIdentityStore::default();
    let sessions = MemorySessionStore::default();
    let tokens = MemoryOAuthTokenStore::default();
    let kv = common::MemoryKvStore::default();
    let user = users
        .create_with_password(
            "reset_user",
            Some("reset@example.test"),
            None,
            None,
            &pero::shared::crypto::hash_secret("oldpassword").unwrap(),
        )
        .await
        .unwrap();
    let (_session, _refresh) = sessions
        .create(user.id, 1, "device", "location")
        .await
        .unwrap();
    kv.set_raw(
        &format!("password_reset:{}", "token-1"),
        serde_json::Value::String(user.id.to_string()),
        60,
    )
    .await
    .unwrap();

    password_reset::complete_reset(
        &users,
        &users,
        &sessions,
        &tokens,
        &kv,
        "token-1",
        "newpassword",
    )
    .await
    .unwrap();

    assert!(
        sessions
            .list_user_session_ids(user.id)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(tokens.revoked_user_count(), 1);
}

#[tokio::test]
async fn user_management_delete_removes_user_and_revokes_tokens() {
    let users = MemoryIdentityStore::default();
    let sessions = MemorySessionStore::default();
    let tokens = MemoryOAuthTokenStore::default();
    let user = users
        .create_with_password(
            "delete_user",
            None,
            None,
            None,
            &pero::shared::crypto::hash_secret("password123").unwrap(),
        )
        .await
        .unwrap();

    pero::application::user_management::disable_user(&users, &sessions, &tokens, user.id)
        .await
        .unwrap();

    assert!(users.find_by_id(user.id).await.unwrap().is_none());
    assert_eq!(tokens.revoked_user_count(), 1);
}

#[tokio::test]
async fn social_login_completes_callback_and_creates_social_user() {
    let social = TestSocialStore::default();
    let users = MemoryIdentityStore::default();
    let kv = common::MemoryKvStore::default();
    let http = TestHttpClient;
    let state_token = "state-login";
    kv.set_raw(
        &state_key(state_token),
        serde_json::to_value(SocialState {
            sso_session_id: "sso-1".into(),
            provider: "google".into(),
            account_login: Some(true),
            account_next: Some("/account".into()),
        })
        .unwrap(),
        60,
    )
    .await
    .unwrap();

    let (user, info, state) = social_login::complete_social_login(
        &social,
        &users,
        &users,
        &kv,
        &http,
        "oauth-code",
        state_token,
        "google",
        "https://auth.example.test/sso/social/google/callback",
    )
    .await
    .unwrap();

    assert_eq!(info.provider_uid, "google-user-1");
    assert_eq!(user.email.as_deref(), Some("social@example.test"));
    assert_eq!(state.account_next.as_deref(), Some("/account"));
    assert!(kv.get_raw(&state_key(state_token)).await.unwrap().is_none());
}

#[tokio::test]
async fn social_binding_links_identity_for_current_user() {
    let social = TestSocialStore::default();
    let users = MemoryIdentityStore::default();
    let kv = common::MemoryKvStore::default();
    let http = TestHttpClient;
    let user = users
        .create_with_password(
            "bind_user",
            None,
            None,
            None,
            &pero::shared::crypto::hash_secret("password123").unwrap(),
        )
        .await
        .unwrap();
    let state_token = "state-bind";
    kv.set_raw(
        &state_key(state_token),
        serde_json::to_value(SocialBindState {
            provider: "google".into(),
            bind_user_id: user.id.to_string(),
        })
        .unwrap(),
        60,
    )
    .await
    .unwrap();

    social_login::complete_social_binding(
        &social,
        &users,
        &kv,
        &http,
        user.id,
        "oauth-code",
        state_token,
        "https://auth.example.test",
    )
    .await
    .unwrap();

    assert!(
        users
            .find_by_user_and_provider(user.id, "google")
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn token_exchange_application_wrappers_return_validation_errors_fast() {
    let noop = common::NoopStore;
    let users = MemoryIdentityStore::default();
    let tokens = MemoryOAuthTokenStore::default();
    let missing_code = TokenRequest {
        grant_type: GrantType::AuthorizationCode,
        code: None,
        redirect_uri: Some("https://app.example.test/callback".into()),
        client_id: Some("client".into()),
        client_secret: Some("secret".into()),
        code_verifier: Some("a".repeat(43)),
        refresh_token: None,
    };
    assert!(
        token_exchange::exchange_authorization_code(
            &noop,
            &tokens,
            &tokens,
            &noop,
            &users,
            &noop,
            5,
            1,
            "https://auth.example.test",
            &missing_code,
        )
        .await
        .is_err()
    );

    let missing_refresh = TokenRequest {
        grant_type: GrantType::RefreshToken,
        code: None,
        redirect_uri: None,
        client_id: Some("client".into()),
        client_secret: Some("secret".into()),
        code_verifier: None,
        refresh_token: None,
    };
    assert!(
        token_exchange::rotate_refresh_token(
            &noop,
            &tokens,
            &tokens,
            &noop,
            &users,
            &noop,
            5,
            1,
            "https://auth.example.test",
            &missing_refresh,
        )
        .await
        .is_err()
    );

    assert!(
        token_exchange::revoke_token(
            &noop,
            &tokens,
            &noop,
            &RevokeRequest {
                token: "refresh".into(),
                token_type_hint: None,
                client_id: None,
                client_secret: Some("secret".into()),
            },
        )
        .await
        .is_err()
    );
}

#[tokio::test]
async fn sso_consent_builds_view_and_issues_authorization_code_redirect() {
    let apps = MemoryAppStore::default();
    let clients = MemoryOAuth2ClientStore::default();
    let users = MemoryIdentityStore::default();
    let sso_sessions = MemorySsoStore::default();
    let tokens = MemoryOAuthTokenStore::default();
    let app = apps
        .create(&CreateAppRequest {
            name: "Consent App".into(),
            code: "consent".into(),
            description: None,
        })
        .await
        .unwrap();
    let client = clients
        .create(
            "consent-client",
            &pero::shared::crypto::hash_secret("secret").unwrap(),
            &pero::domain::oauth::models::CreateClientRequest {
                app_id: app.id,
                client_name: "Consent Client".into(),
                redirect_uris: vec!["https://app.example.test/callback".into()],
                grant_types: vec!["authorization_code".into(), "refresh_token".into()],
                scopes: vec!["openid".into(), "email".into()],
                post_logout_redirect_uris: vec![],
            },
        )
        .await
        .unwrap();
    let user = users
        .create_with_password(
            "consent_user",
            Some("consent@example.test"),
            None,
            None,
            &pero::shared::crypto::hash_secret("password123").unwrap(),
        )
        .await
        .unwrap();
    let sso = SsoSession {
        authorize_params: AuthorizeParams {
            client_id: client.client_id,
            redirect_uri: "https://app.example.test/callback".into(),
            response_type: "code".into(),
            scope: Some("openid email".into()),
            state: Some("state-1".into()),
            code_challenge: "a".repeat(43),
            code_challenge_method: "S256".into(),
            nonce: Some("nonce".into()),
        },
        user_id: Some(user.id),
        authenticated: true,
        auth_time: Some(123),
    };
    let sid = sso_sessions.create(&sso, 60).await.unwrap();

    let view = pero::domain::sso::service::build_consent_view(&clients, &apps, &sso_sessions, &sso)
        .await
        .unwrap();
    assert_eq!(view.client_name, "Consent Client");
    assert_eq!(view.scopes, vec!["openid", "email"]);

    let redirect = pero::domain::sso::service::handle_consent_action(
        &clients,
        &apps,
        &users,
        &sso_sessions,
        &tokens,
        5,
        &sid,
        &sso,
        pero::domain::sso::models::ConsentDecision::Allow,
        Some("account-session"),
    )
    .await
    .unwrap();
    assert!(redirect.starts_with("https://app.example.test/callback?"));
    assert!(redirect.contains("code="));
    assert!(redirect.contains("state=state-1"));
    assert!(sso_sessions.get(&sid).await.unwrap().is_none());
}

#[tokio::test]
async fn user_service_updates_attributes_and_unbinds_non_password_identity() {
    let users = MemoryIdentityStore::default();
    let sessions = MemorySessionStore::default();
    let tokens = MemoryOAuthTokenStore::default();
    let abac_cache = MemoryAbacStore::default();
    let response = pero::domain::user::service::register_user(
        &users,
        &sessions,
        &common::NoopStore,
        &RegisterRequest {
            username: "svc_user".into(),
            email: Some("svc@example.test".into()),
            phone: Some("+12025550123".into()),
            nickname: Some("Service".into()),
            password: "password123".into(),
        },
        "device",
        "location",
        5,
        1,
    )
    .await
    .unwrap();
    let user_id = response.user.id;

    let updated_me = pero::domain::user::service::update_me(
        &users,
        user_id,
        &UpdateMeRequest {
            email: FieldUpdate::Set("svc2@example.test".into()),
            nickname: FieldUpdate::Set("Svc2".into()),
            avatar_url: FieldUpdate::Unchanged,
            phone: FieldUpdate::Clear,
        },
    )
    .await
    .unwrap();
    assert_eq!(updated_me.email.as_deref(), Some("svc2@example.test"));
    assert!(!updated_me.email_verified);

    let disabled = pero::domain::user::service::update_user(
        &users,
        &sessions,
        &tokens,
        user_id,
        &UpdateUserRequest {
            username: FieldUpdate::Set("svc_user_2".into()),
            email: FieldUpdate::Unchanged,
            phone: FieldUpdate::Unchanged,
            nickname: FieldUpdate::Unchanged,
            avatar_url: FieldUpdate::Unchanged,
            status: FieldUpdate::Set(0),
        },
    )
    .await
    .unwrap();
    assert_eq!(disabled.status, 0);
    assert_eq!(tokens.revoked_user_count(), 1);

    pero::domain::user::service::set_user_attributes(
        &users,
        &users,
        &abac_cache,
        60,
        user_id,
        &SetAttributes {
            attributes: vec![AttributeItem {
                key: "department".into(),
                value: "engineering".into(),
            }],
        },
    )
    .await
    .unwrap();
    assert_eq!(
        UserAttributeStore::list_by_user(&users, user_id)
            .await
            .unwrap()
            .len(),
        1
    );

    pero::domain::user::service::delete_user_attribute(
        &users,
        &users,
        &abac_cache,
        60,
        user_id,
        "department",
    )
    .await
    .unwrap();
    assert!(
        UserAttributeStore::list_by_user(&users, user_id)
            .await
            .unwrap()
            .is_empty()
    );

    users
        .create_social(user_id, "google", "google-user")
        .await
        .unwrap();
    assert!(
        pero::domain::user::service::unbind_identity(&users, user_id, "password")
            .await
            .is_err()
    );
    assert!(
        pero::domain::user::service::unbind_identity(&users, user_id, "google")
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn auth_service_registers_authenticates_and_changes_password_with_revocation() {
    let users = MemoryIdentityStore::default();
    let sessions = MemorySessionStore::default();
    let tokens = MemoryOAuthTokenStore::default();

    let user = AuthService::register_user_with_password(
        &users,
        &users,
        "auth_user",
        Some("auth@example.test"),
        None,
        Some("Auth"),
        "password123",
    )
    .await
    .unwrap();

    assert!(
        AuthService::authenticate_with_password(
            &users,
            &users,
            &IdentifierType::Email,
            "auth@example.test",
            "password123",
        )
        .await
        .is_err()
    );
    users
        .set_email_verified(user.id, "auth@example.test")
        .await
        .unwrap();
    assert_eq!(
        AuthService::authenticate_with_password(
            &users,
            &users,
            &IdentifierType::Email,
            "auth@example.test",
            "password123",
        )
        .await
        .unwrap()
        .id,
        user.id
    );
    assert!(
        AuthService::authenticate_with_password(
            &users,
            &users,
            &IdentifierType::Username,
            "auth_user",
            "wrongpassword",
        )
        .await
        .is_err()
    );

    let (_session, _refresh) = sessions
        .create(user.id, 1, "device", "location")
        .await
        .unwrap();
    assert!(
        AuthService::change_password(
            &users,
            &users,
            &sessions,
            &tokens,
            user.id,
            "password123",
            "password123",
        )
        .await
        .is_err()
    );
    assert!(
        AuthService::change_password(
            &users,
            &users,
            &sessions,
            &tokens,
            user.id,
            "wrongpassword",
            "newpassword123",
        )
        .await
        .is_err()
    );
    AuthService::change_password(
        &users,
        &users,
        &sessions,
        &tokens,
        user.id,
        "password123",
        "newpassword123",
    )
    .await
    .unwrap();
    assert!(
        sessions
            .list_user_session_ids(user.id)
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(tokens.revoked_user_count(), 1);
    assert!(
        AuthService::authenticate_with_password(
            &users,
            &users,
            &IdentifierType::Username,
            "auth_user",
            "newpassword123",
        )
        .await
        .is_ok()
    );
}
