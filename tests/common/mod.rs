#![allow(dead_code)]

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use chrono::Utc;
use http_body_util::BodyExt;
use pero::api::build_router;
use pero::config::{
    AbacConfig, AppConfig, CorsConfig, DatabaseConfig, DocsConfig, JwtConfig, LogConfig,
    OAuth2Config, OidcConfig, RedisConfig, ServerConfig, SsoConfig,
};
use pero::domain::abac::repo::{AbacCacheStore, AbacStore, PolicyFilter};
use pero::domain::abac::service::AttachedPolicies;
use pero::domain::app::models::{App, CreateAppRequest, UpdateAppRequest};
use pero::domain::app::repo::AppStore;
use pero::domain::auth::repo::SessionStore;
use pero::domain::auth::session::{IdentitySession, build_refresh_token, hash_refresh_token};
use pero::domain::credential::entity::Identity;
use pero::domain::credential::repo::IdentityStore;
use pero::domain::federation::entity::{
    CreateSocialProviderRequest, SocialProvider, UpdateSocialProviderRequest,
};
use pero::domain::federation::http::HttpClient;
use pero::domain::federation::repo::SocialStore;
use pero::domain::oauth::entity::{AuthorizationCode, OAuth2Client, RefreshToken, TokenFamily};
use pero::domain::oauth::models::{CreateClientRequest, UpdateClientRequest};
use pero::domain::oauth::repo::{
    AccessTokenParams, AuthorizationCodeStore, CreateAuthCodeParams, OAuth2ClientStore,
    RefreshTokenStore, TokenFamilyStore, TokenSigner,
};
use pero::domain::sso::models::SsoSession;
use pero::domain::sso::repo::SsoSessionStore;
use pero::domain::user::dto::{AttributeItem, UserAttribute};
use pero::domain::user::entity::User;
use pero::domain::user::models::{UpdateMeRequest, UpdateUserRequest};
use pero::domain::user::repo::{UserAttributeStore, UserStore};
use pero::infra::jwt::JwtKeys;
use pero::infra::repo::JwtTokenSigner;
use pero::infra::repo::build_repos;
use pero::shared::error::AppError;
use pero::shared::kv::KvStore;
use pero::shared::patch::FieldUpdate;
use pero::shared::state::{AppState, Repos};
use serde_json::Value;
use tower::ServiceExt;
use uuid::Uuid;

#[derive(Clone)]
pub struct TestApp {
    pub app: Router,
    pub identity: Arc<MemoryIdentityStore>,
    pub state: AppState,
}

impl TestApp {
    pub fn new() -> Self {
        Self::with_abac_default_action("deny")
    }

    pub fn admin_allowed() -> Self {
        Self::with_abac_default_action("allow")
    }

    fn with_abac_default_action(default_action: &str) -> Self {
        let identity = Arc::new(MemoryIdentityStore::default());
        let sessions = Arc::new(MemorySessionStore::default());
        let token_store = Arc::new(MemoryOAuthTokenStore::default());
        let apps = Arc::new(MemoryAppStore::default());
        let oauth2_clients = Arc::new(MemoryOAuth2ClientStore::default());
        let policies = Arc::new(MemoryAbacStore::default());
        let social = Arc::new(MemorySocialStore::default());
        let noop = Arc::new(NoopStore::default());
        let mut cfg = test_config();
        cfg.abac.default_action = default_action.into();
        let keys = Arc::new(test_jwt_keys(&cfg.oidc));
        let repos = Repos {
            users: identity.clone(),
            identities: identity.clone(),
            user_attributes: identity.clone(),
            sessions,
            sso_sessions: Arc::new(MemorySsoStore::default()),
            policies: policies.clone(),
            abac_cache: policies,
            oauth2_clients,
            auth_codes: token_store.clone(),
            token_families: token_store.clone(),
            refresh_tokens: token_store,
            social,
            apps,
            kv: Arc::new(MemoryKvStore::default()),
            http: noop.clone(),
            token_signer: Arc::new(JwtTokenSigner::new(
                keys.clone(),
                cfg.oauth2.access_token_ttl_minutes,
                cfg.oidc.issuer.clone(),
            )),
        };
        let state = AppState {
            repos: Arc::new(repos),
            jwt_keys: keys,
            config: Arc::new(cfg),
            discovery_doc: Arc::new(std::sync::OnceLock::new()),
            jwks_doc: Arc::new(std::sync::OnceLock::new()),
        };
        Self {
            app: build_router(state.clone()),
            identity,
            state,
        }
    }
}

pub struct RealTestApp {
    pub app: Router,
    pub state: AppState,
    pub db: sqlx::PgPool,
    pub cache: pero::infra::cache::Pool,
    pub prefix: String,
}

impl RealTestApp {
    pub async fn new(prefix: &str) -> Self {
        let cfg = real_config();
        let db = pero::infra::db::init_pool(&cfg.database)
            .await
            .expect("real postgres test database should be reachable");
        apply_migrations(&db).await;
        let cache = pero::infra::cache::init_pool(&cfg.redis)
            .await
            .expect("real redis test database should be reachable");
        let keys = Arc::new(test_jwt_keys(&cfg.oidc));
        let repos = build_repos(db.clone(), cache.clone(), keys.clone(), &cfg);
        let state = AppState {
            repos: Arc::new(repos),
            jwt_keys: keys,
            config: Arc::new(cfg),
            discovery_doc: Arc::new(std::sync::OnceLock::new()),
            jwks_doc: Arc::new(std::sync::OnceLock::new()),
        };
        Self {
            app: build_router(state.clone()),
            state,
            db,
            cache,
            prefix: prefix.to_string(),
        }
    }

    pub async fn cleanup(&self) {
        cleanup_real_data(&self.db, &self.cache, &self.prefix).await;
    }
}

impl Drop for RealTestApp {
    fn drop(&mut self) {
        let db = self.db.clone();
        let cache = self.cache.clone();
        let prefix = self.prefix.clone();
        tokio::spawn(async move {
            cleanup_real_data(&db, &cache, &prefix).await;
        });
    }
}

pub fn test_config() -> AppConfig {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    AppConfig {
        server: ServerConfig {
            host: "127.0.0.1".into(),
            port: 0,
            request_body_limit_bytes: 1024 * 1024,
            rate_limit_rpm: 10_000,
            cleanup_interval_secs: 3600,
        },
        database: DatabaseConfig {
            url: "postgres://unused".into(),
            max_connections: 1,
            min_connections: 0,
        },
        redis: RedisConfig {
            url: "redis://127.0.0.1:0/".into(),
            pool_size: 1,
        },
        jwt: JwtConfig {
            access_ttl_minutes: 5,
            refresh_ttl_days: 1,
        },
        log: LogConfig {
            level: "error".into(),
            dir: "target/test-logs".into(),
            rotation: "never".into(),
        },
        abac: AbacConfig {
            default_action: "deny".into(),
            policy_cache_ttl_seconds: 60,
        },
        oidc: OidcConfig {
            issuer: "https://auth.test".into(),
            private_key_path: root.join("config/keys/private.pem").display().to_string(),
            public_key_path: root.join("config/keys/public.pem").display().to_string(),
            key_id: "test-key".into(),
        },
        oauth2: OAuth2Config {
            auth_code_ttl_minutes: 5,
            access_token_ttl_minutes: 5,
            refresh_token_ttl_days: 1,
        },
        sso: SsoConfig {
            cookie_secure: false,
            ..SsoConfig::default()
        },
        docs: DocsConfig::default(),
        cors: CorsConfig::default(),
    }
}

pub fn real_config() -> AppConfig {
    let mut cfg = test_config();
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let raw = std::fs::read_to_string(root.join("config/test.toml"))
        .expect("config/test.toml should exist");
    let value: toml::Value = toml::from_str(&raw).expect("config/test.toml should be valid TOML");
    if let Some(url) = value
        .get("database")
        .and_then(|v| v.get("url"))
        .and_then(|v| v.as_str())
    {
        cfg.database.url = std::env::var("PERO_TEST_DATABASE_URL").unwrap_or_else(|_| url.into());
    }
    if let Some(max) = value
        .get("database")
        .and_then(|v| v.get("max_connections"))
        .and_then(|v| v.as_integer())
    {
        cfg.database.max_connections = max as u32;
    }
    if let Some(min) = value
        .get("database")
        .and_then(|v| v.get("min_connections"))
        .and_then(|v| v.as_integer())
    {
        cfg.database.min_connections = min as u32;
    }
    if let Some(url) = value
        .get("redis")
        .and_then(|v| v.get("url"))
        .and_then(|v| v.as_str())
    {
        cfg.redis.url = std::env::var("PERO_TEST_REDIS_URL").unwrap_or_else(|_| url.into());
    }
    if let Some(size) = value
        .get("redis")
        .and_then(|v| v.get("pool_size"))
        .and_then(|v| v.as_integer())
    {
        cfg.redis.pool_size = size as usize;
    }
    cfg.abac.default_action = "allow".into();
    cfg
}

async fn apply_migrations(db: &sqlx::PgPool) {
    let migrations = [
        include_str!("../../migrations/001_init.sql"),
        include_str!("../../migrations/002_token_families.sql"),
    ];
    for migration in migrations {
        for statement in migration
            .split(';')
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            if let Err(err) = sqlx::query(statement).execute(db).await {
                let duplicate_relation = matches!(
                    &err,
                    sqlx::Error::Database(db_err) if db_err.code().as_deref() == Some("42P07")
                );
                if !duplicate_relation {
                    panic!("migration statement should apply: {err}");
                }
            }
        }
    }
}

async fn cleanup_real_data(db: &sqlx::PgPool, cache: &pero::infra::cache::Pool, prefix: &str) {
    let like = format!("{prefix}%");
    let _ = sqlx::query("DELETE FROM social_providers WHERE name LIKE $1")
        .bind(&like)
        .execute(db)
        .await;
    let _ = sqlx::query("DELETE FROM apps WHERE code LIKE $1 OR name LIKE $1")
        .bind(&like)
        .execute(db)
        .await;
    let _ = sqlx::query("DELETE FROM policies WHERE name LIKE $1")
        .bind(&like)
        .execute(db)
        .await;
    let _ = sqlx::query("DELETE FROM users WHERE username LIKE $1 OR email LIKE $1")
        .bind(&like)
        .execute(db)
        .await;
    let _ = pero::infra::cache::delete_by_pattern(cache, &format!("*{prefix}*")).await;
}

pub fn test_jwt_keys(cfg: &OidcConfig) -> JwtKeys {
    JwtKeys::load(cfg).expect("test keys should load")
}

fn dummy_redis_pool() -> pero::infra::cache::Pool {
    let client = redis::Client::open("redis://127.0.0.1:0/").expect("valid redis url");
    let manager = pero::infra::cache::RedisManager::new(client);
    deadpool::managed::Pool::builder(manager)
        .max_size(1)
        .build()
        .expect("dummy redis pool")
}

pub async fn json_request(
    app: Router,
    method: Method,
    uri: &str,
    body: Option<Value>,
    bearer: Option<&str>,
) -> (StatusCode, Value) {
    let mut headers = vec![];
    if let Some(token) = bearer {
        headers.push(("authorization", format!("Bearer {token}")));
    }
    json_request_with_headers(app, method, uri, body, &headers).await
}

pub async fn json_request_with_headers(
    app: Router,
    method: Method,
    uri: &str,
    body: Option<Value>,
    headers: &[(&str, String)],
) -> (StatusCode, Value) {
    let mut builder = Request::builder().method(method).uri(uri);
    for (name, value) in headers {
        builder = builder.header(*name, value);
    }
    let body = match body {
        Some(value) => {
            builder = builder.header("content-type", "application/json");
            Body::from(serde_json::to_vec(&value).expect("json body"))
        }
        None => Body::empty(),
    };
    let response = app
        .oneshot(builder.body(body).expect("request"))
        .await
        .expect("response");
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, value)
}

pub async fn form_request_with_headers(
    app: Router,
    method: Method,
    uri: &str,
    form: &[(&str, String)],
    headers: &[(&str, String)],
) -> (StatusCode, Value) {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/x-www-form-urlencoded");
    for (name, value) in headers {
        builder = builder.header(*name, value);
    }
    let body = form
        .iter()
        .map(|(key, value)| {
            format!(
                "{}={}",
                urlencoding::encode(key),
                urlencoding::encode(value)
            )
        })
        .collect::<Vec<_>>()
        .join("&");
    let response = app
        .oneshot(builder.body(Body::from(body)).expect("request"))
        .await
        .expect("response");
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, value)
}

pub async fn text_request_with_headers(
    app: Router,
    method: Method,
    uri: &str,
    headers: &[(&str, String)],
) -> (StatusCode, String) {
    let mut builder = Request::builder().method(method).uri(uri);
    for (name, value) in headers {
        builder = builder.header(*name, value);
    }
    let response = app
        .oneshot(builder.body(Body::empty()).expect("request"))
        .await
        .expect("response");
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    let body = String::from_utf8(bytes.to_vec()).expect("utf8 response body");
    (status, body)
}

#[derive(Default)]
pub struct MemoryIdentityStore {
    users: Mutex<HashMap<Uuid, User>>,
    identities: Mutex<Vec<Identity>>,
    attrs: Mutex<HashMap<Uuid, Vec<UserAttribute>>>,
}

impl MemoryIdentityStore {
    pub fn user_count(&self) -> usize {
        self.users.lock().unwrap().len()
    }

    fn user(
        id: Uuid,
        username: &str,
        email: Option<&str>,
        phone: Option<&str>,
        nickname: Option<&str>,
    ) -> User {
        let now = Utc::now();
        User {
            id,
            username: username.into(),
            email: email.map(str::to_string),
            phone: phone.map(str::to_string),
            nickname: nickname.map(str::to_string),
            avatar_url: None,
            email_verified: email.is_none(),
            phone_verified: phone.is_none(),
            status: 1,
            created_at: now,
            updated_at: now,
        }
    }

    fn identity(user_id: Uuid, provider: &str, uid: &str, credential: Option<&str>) -> Identity {
        let now = Utc::now();
        Identity {
            id: Uuid::new_v4(),
            user_id,
            provider: provider.into(),
            provider_uid: uid.into(),
            credential: credential.map(str::to_string),
            verified: true,
            created_at: now,
            updated_at: now,
        }
    }
}

#[async_trait]
impl UserStore for MemoryIdentityStore {
    async fn find_by_id(&self, id: Uuid) -> Result<Option<User>, AppError> {
        Ok(self.users.lock().unwrap().get(&id).cloned())
    }

    async fn find_by_username(&self, username: &str) -> Result<Option<User>, AppError> {
        Ok(self
            .users
            .lock()
            .unwrap()
            .values()
            .find(|u| u.username == username)
            .cloned())
    }

    async fn find_by_email(&self, email: &str) -> Result<Option<User>, AppError> {
        Ok(self
            .users
            .lock()
            .unwrap()
            .values()
            .find(|u| u.email.as_deref() == Some(email))
            .cloned())
    }

    async fn find_by_phone(&self, phone: &str) -> Result<Option<User>, AppError> {
        Ok(self
            .users
            .lock()
            .unwrap()
            .values()
            .find(|u| u.phone.as_deref() == Some(phone))
            .cloned())
    }

    async fn list(&self, page: i64, page_size: i64) -> Result<(Vec<User>, i64), AppError> {
        let mut users: Vec<_> = self.users.lock().unwrap().values().cloned().collect();
        users.sort_by(|a, b| a.username.cmp(&b.username));
        let total = users.len() as i64;
        let start = ((page.max(1) - 1) * page_size.max(1)) as usize;
        let end = (start + page_size.max(1) as usize).min(users.len());
        Ok((users.get(start..end).unwrap_or(&[]).to_vec(), total))
    }

    async fn update_admin(
        &self,
        id: Uuid,
        req: &UpdateUserRequest,
        reset_email_verified: bool,
        reset_phone_verified: bool,
    ) -> Result<User, AppError> {
        let mut users = self.users.lock().unwrap();
        let user = users
            .get_mut(&id)
            .ok_or_else(|| AppError::NotFound("user".into()))?;
        if let FieldUpdate::Set(value) = &req.username {
            user.username = value.clone();
        }
        if let FieldUpdate::Set(value) = &req.email {
            user.email = Some(value.clone());
        }
        if matches!(req.email, FieldUpdate::Clear) {
            user.email = None;
        }
        if let FieldUpdate::Set(value) = &req.phone {
            user.phone = Some(value.clone());
        }
        if matches!(req.phone, FieldUpdate::Clear) {
            user.phone = None;
        }
        if let FieldUpdate::Set(value) = &req.nickname {
            user.nickname = Some(value.clone());
        }
        if matches!(req.nickname, FieldUpdate::Clear) {
            user.nickname = None;
        }
        if let FieldUpdate::Set(value) = &req.avatar_url {
            user.avatar_url = Some(value.clone());
        }
        if matches!(req.avatar_url, FieldUpdate::Clear) {
            user.avatar_url = None;
        }
        if let FieldUpdate::Set(value) = &req.status {
            user.status = *value;
        }
        if reset_email_verified {
            user.email_verified = false;
        }
        if reset_phone_verified {
            user.phone_verified = false;
        }
        Ok(user.clone())
    }

    async fn update_self(
        &self,
        id: Uuid,
        req: &UpdateMeRequest,
        reset_email_verified: bool,
        reset_phone_verified: bool,
    ) -> Result<User, AppError> {
        let mut users = self.users.lock().unwrap();
        let user = users
            .get_mut(&id)
            .ok_or_else(|| AppError::NotFound("user".into()))?;
        if let FieldUpdate::Set(value) = &req.email {
            user.email = Some(value.clone());
        }
        if matches!(req.email, FieldUpdate::Clear) {
            user.email = None;
        }
        if let FieldUpdate::Set(value) = &req.nickname {
            user.nickname = Some(value.clone());
        }
        if matches!(req.nickname, FieldUpdate::Clear) {
            user.nickname = None;
        }
        if let FieldUpdate::Set(value) = &req.avatar_url {
            user.avatar_url = Some(value.clone());
        }
        if matches!(req.avatar_url, FieldUpdate::Clear) {
            user.avatar_url = None;
        }
        if let FieldUpdate::Set(value) = &req.phone {
            user.phone = Some(value.clone());
        }
        if matches!(req.phone, FieldUpdate::Clear) {
            user.phone = None;
        }
        if reset_email_verified {
            user.email_verified = false;
        }
        if reset_phone_verified {
            user.phone_verified = false;
        }
        Ok(user.clone())
    }

    async fn delete(&self, id: Uuid) -> Result<(), AppError> {
        self.users.lock().unwrap().remove(&id);
        Ok(())
    }

    async fn set_email_verified(&self, user_id: Uuid, email: &str) -> Result<(), AppError> {
        if let Some(user) = self.users.lock().unwrap().get_mut(&user_id) {
            if user.email.as_deref() == Some(email) {
                user.email_verified = true;
            }
        }
        Ok(())
    }

    async fn set_phone_verified(&self, user_id: Uuid, phone: &str) -> Result<(), AppError> {
        if let Some(user) = self.users.lock().unwrap().get_mut(&user_id) {
            if user.phone.as_deref() == Some(phone) {
                user.phone_verified = true;
            }
        }
        Ok(())
    }

    async fn check_new_user_conflicts(
        &self,
        username: &str,
        email: Option<&str>,
        phone: Option<&str>,
    ) -> Result<(), AppError> {
        if self.find_by_username(username).await?.is_some() {
            return Err(AppError::Conflict("username exists".into()));
        }
        if let Some(email) = email {
            if self.find_by_email(email).await?.is_some() {
                return Err(AppError::Conflict("email exists".into()));
            }
        }
        if let Some(phone) = phone {
            if self.find_by_phone(phone).await?.is_some() {
                return Err(AppError::Conflict("phone exists".into()));
            }
        }
        Ok(())
    }

    async fn check_update_user_conflicts(
        &self,
        id: Uuid,
        username: Option<&str>,
        email: Option<&str>,
        phone: Option<&str>,
    ) -> Result<(), AppError> {
        let users = self.users.lock().unwrap();
        if username.is_some_and(|v| users.values().any(|u| u.id != id && u.username == v)) {
            return Err(AppError::Conflict("username exists".into()));
        }
        if email.is_some_and(|v| {
            users
                .values()
                .any(|u| u.id != id && u.email.as_deref() == Some(v))
        }) {
            return Err(AppError::Conflict("email exists".into()));
        }
        if phone.is_some_and(|v| {
            users
                .values()
                .any(|u| u.id != id && u.phone.as_deref() == Some(v))
        }) {
            return Err(AppError::Conflict("phone exists".into()));
        }
        Ok(())
    }

    async fn create_with_password(
        &self,
        username: &str,
        email: Option<&str>,
        phone: Option<&str>,
        nickname: Option<&str>,
        password_hash: &str,
    ) -> Result<User, AppError> {
        self.check_new_user_conflicts(username, email, phone)
            .await?;
        let user = Self::user(Uuid::new_v4(), username, email, phone, nickname);
        self.users.lock().unwrap().insert(user.id, user.clone());
        self.identities.lock().unwrap().push(Self::identity(
            user.id,
            "password",
            &user.id.to_string(),
            Some(password_hash),
        ));
        Ok(user)
    }

    async fn find_by_social_identity(
        &self,
        provider: &str,
        provider_uid: &str,
    ) -> Result<Option<User>, AppError> {
        let user_id = self
            .identities
            .lock()
            .unwrap()
            .iter()
            .find(|i| i.provider == provider && i.provider_uid == provider_uid)
            .map(|i| i.user_id);
        Ok(user_id.and_then(|id| self.users.lock().unwrap().get(&id).cloned()))
    }

    async fn link_social_identity(
        &self,
        user_id: Uuid,
        provider: &str,
        provider_uid: &str,
    ) -> Result<(), AppError> {
        self.identities
            .lock()
            .unwrap()
            .push(Self::identity(user_id, provider, provider_uid, None));
        Ok(())
    }

    async fn set_email_verified_flag(&self, user_id: Uuid) -> Result<(), AppError> {
        if let Some(user) = self.users.lock().unwrap().get_mut(&user_id) {
            user.email_verified = true;
        }
        Ok(())
    }

    async fn create_social_user(
        &self,
        username: &str,
        email: Option<&str>,
        nickname: Option<&str>,
        provider: &str,
        provider_uid: &str,
        email_verified: bool,
    ) -> Result<User, AppError> {
        let mut user = Self::user(Uuid::new_v4(), username, email, None, nickname);
        user.email_verified = email_verified;
        self.users.lock().unwrap().insert(user.id, user.clone());
        self.link_social_identity(user.id, provider, provider_uid)
            .await?;
        Ok(user)
    }

    async fn resolve_unique_username(&self, base: &str) -> Result<String, AppError> {
        for i in 0..100 {
            let candidate = if i == 0 {
                base.to_string()
            } else {
                format!("{base}_{i}")
            };
            if self.find_by_username(&candidate).await?.is_none() {
                return Ok(candidate);
            }
        }
        Err(AppError::Conflict(
            "could not generate unique username".into(),
        ))
    }
}

#[async_trait]
impl IdentityStore for MemoryIdentityStore {
    async fn create_password(
        &self,
        user_id: Uuid,
        password_hash: &str,
    ) -> Result<Identity, AppError> {
        let identity = Self::identity(
            user_id,
            "password",
            &user_id.to_string(),
            Some(password_hash),
        );
        self.identities.lock().unwrap().push(identity.clone());
        Ok(identity)
    }

    async fn create_social(
        &self,
        user_id: Uuid,
        provider: &str,
        provider_uid: &str,
    ) -> Result<Identity, AppError> {
        let identity = Self::identity(user_id, provider, provider_uid, None);
        self.identities.lock().unwrap().push(identity.clone());
        Ok(identity)
    }

    async fn find_by_user_and_provider(
        &self,
        user_id: Uuid,
        provider: &str,
    ) -> Result<Option<Identity>, AppError> {
        Ok(self
            .identities
            .lock()
            .unwrap()
            .iter()
            .find(|i| i.user_id == user_id && i.provider == provider)
            .cloned())
    }

    async fn find_by_provider(
        &self,
        provider: &str,
        provider_uid: &str,
    ) -> Result<Option<Identity>, AppError> {
        Ok(self
            .identities
            .lock()
            .unwrap()
            .iter()
            .find(|i| i.provider == provider && i.provider_uid == provider_uid)
            .cloned())
    }

    async fn list_by_user(&self, user_id: Uuid) -> Result<Vec<Identity>, AppError> {
        Ok(self
            .identities
            .lock()
            .unwrap()
            .iter()
            .filter(|i| i.user_id == user_id)
            .cloned()
            .collect())
    }

    async fn delete(&self, user_id: Uuid, provider: &str) -> Result<(), AppError> {
        self.identities
            .lock()
            .unwrap()
            .retain(|i| !(i.user_id == user_id && i.provider == provider));
        Ok(())
    }

    async fn count_by_user(&self, user_id: Uuid) -> Result<i64, AppError> {
        Ok(self
            .identities
            .lock()
            .unwrap()
            .iter()
            .filter(|i| i.user_id == user_id)
            .count() as i64)
    }

    async fn update_credential(
        &self,
        user_id: Uuid,
        provider: &str,
        credential: &str,
    ) -> Result<(), AppError> {
        if let Some(identity) = self
            .identities
            .lock()
            .unwrap()
            .iter_mut()
            .find(|i| i.user_id == user_id && i.provider == provider)
        {
            identity.credential = Some(credential.into());
        }
        Ok(())
    }
}

#[async_trait]
impl UserAttributeStore for MemoryIdentityStore {
    async fn list_by_user(&self, user_id: Uuid) -> Result<Vec<UserAttribute>, AppError> {
        Ok(self
            .attrs
            .lock()
            .unwrap()
            .get(&user_id)
            .map(|items| {
                items
                    .iter()
                    .map(|item| UserAttribute {
                        id: item.id,
                        user_id: item.user_id,
                        key: item.key.clone(),
                        value: item.value.clone(),
                    })
                    .collect()
            })
            .unwrap_or_default())
    }

    async fn upsert(&self, user_id: Uuid, items: &[AttributeItem]) -> Result<(), AppError> {
        let mut attrs = self.attrs.lock().unwrap();
        let entry = attrs.entry(user_id).or_default();
        for item in items {
            if let Some(existing) = entry.iter_mut().find(|attr| attr.key == item.key) {
                existing.value = item.value.clone();
            } else {
                entry.push(UserAttribute {
                    id: Uuid::new_v4(),
                    user_id,
                    key: item.key.clone(),
                    value: item.value.clone(),
                });
            }
        }
        Ok(())
    }

    async fn delete_by_user(&self, user_id: Uuid, key: &str) -> Result<(), AppError> {
        if let Some(items) = self.attrs.lock().unwrap().get_mut(&user_id) {
            items.retain(|item| item.key != key);
        }
        Ok(())
    }
}

#[derive(Default)]
pub struct MemorySessionStore {
    sessions: Mutex<HashMap<String, IdentitySession>>,
    user_index: Mutex<HashMap<Uuid, HashSet<String>>>,
}

#[async_trait]
impl SessionStore for MemorySessionStore {
    async fn create(
        &self,
        user_id: Uuid,
        _ttl_days: i64,
        device: &str,
        location: &str,
    ) -> Result<(IdentitySession, String), AppError> {
        let session_id = Uuid::new_v4().to_string();
        let refresh = build_refresh_token(&session_id);
        let session = IdentitySession {
            session_id: session_id.clone(),
            user_id,
            refresh_token_hash: hash_refresh_token(&refresh),
            previous_refresh_token_hash: None,
            created_at: Utc::now().timestamp(),
            rotated_at: Utc::now().timestamp(),
            device: device.into(),
            location: location.into(),
        };
        self.sessions
            .lock()
            .unwrap()
            .insert(session_id.clone(), session.clone());
        self.user_index
            .lock()
            .unwrap()
            .entry(user_id)
            .or_default()
            .insert(session_id);
        Ok((session, refresh))
    }

    async fn get(&self, session_id: &str) -> Result<Option<IdentitySession>, AppError> {
        Ok(self.sessions.lock().unwrap().get(session_id).cloned())
    }

    async fn rotate(
        &self,
        session_id: &str,
        old_hash: &str,
        new_token: &str,
        _ttl_days: i64,
    ) -> Result<bool, AppError> {
        let mut sessions = self.sessions.lock().unwrap();
        let Some(session) = sessions.get_mut(session_id) else {
            return Ok(false);
        };
        if session.refresh_token_hash != old_hash {
            return Ok(false);
        }
        session.previous_refresh_token_hash = Some(old_hash.into());
        session.refresh_token_hash = hash_refresh_token(new_token);
        session.rotated_at = Utc::now().timestamp();
        Ok(true)
    }

    async fn revoke(&self, session_id: &str) -> Result<(), AppError> {
        self.sessions.lock().unwrap().remove(session_id);
        Ok(())
    }

    async fn revoke_all_for_user(&self, user_id: Uuid) -> Result<(), AppError> {
        let ids = self
            .user_index
            .lock()
            .unwrap()
            .remove(&user_id)
            .unwrap_or_default();
        let mut sessions = self.sessions.lock().unwrap();
        for id in ids {
            sessions.remove(&id);
        }
        Ok(())
    }

    async fn list_user_session_ids(&self, user_id: Uuid) -> Result<Vec<String>, AppError> {
        Ok(self
            .user_index
            .lock()
            .unwrap()
            .get(&user_id)
            .map(|set| set.iter().cloned().collect())
            .unwrap_or_default())
    }

    async fn verify(&self, session_id: &str, user_id: Uuid) -> Result<IdentitySession, AppError> {
        let session = self.get(session_id).await?.ok_or(AppError::Unauthorized)?;
        if session.user_id != user_id {
            return Err(AppError::Unauthorized);
        }
        Ok(session)
    }
}

#[derive(Default)]
pub struct MemorySsoStore {
    sessions: Mutex<HashMap<String, SsoSession>>,
}

#[async_trait]
impl SsoSessionStore for MemorySsoStore {
    async fn create(&self, session: &SsoSession, _ttl_seconds: i64) -> Result<String, AppError> {
        let id = Uuid::new_v4().to_string();
        self.sessions
            .lock()
            .unwrap()
            .insert(id.clone(), session.clone());
        Ok(id)
    }

    async fn get(&self, session_id: &str) -> Result<Option<SsoSession>, AppError> {
        Ok(self.sessions.lock().unwrap().get(session_id).cloned())
    }

    async fn update(
        &self,
        session_id: &str,
        session: &SsoSession,
        _ttl_seconds: i64,
    ) -> Result<(), AppError> {
        self.sessions
            .lock()
            .unwrap()
            .insert(session_id.into(), session.clone());
        Ok(())
    }

    async fn delete(&self, session_id: &str) -> Result<(), AppError> {
        self.sessions.lock().unwrap().remove(session_id);
        Ok(())
    }
}

#[derive(Default)]
pub struct MemoryOAuthTokenStore {
    revoked_users: Mutex<HashSet<Uuid>>,
    auth_codes: Mutex<HashMap<String, AuthorizationCode>>,
    active_refresh: Mutex<HashMap<String, RefreshToken>>,
    revoked_refresh: Mutex<HashMap<String, RefreshToken>>,
    revoked_families: Mutex<HashSet<Uuid>>,
    revoked_owned: Mutex<HashSet<String>>,
}

impl MemoryOAuthTokenStore {
    pub fn revoked_user_count(&self) -> usize {
        self.revoked_users.lock().unwrap().len()
    }

    pub fn revoked_family_count(&self) -> usize {
        self.revoked_families.lock().unwrap().len()
    }

    pub fn revoked_owned_count(&self) -> usize {
        self.revoked_owned.lock().unwrap().len()
    }
}

fn clone_auth_code(code: &AuthorizationCode) -> AuthorizationCode {
    AuthorizationCode {
        code: code.code.clone(),
        client_id: code.client_id,
        user_id: code.user_id,
        redirect_uri: code.redirect_uri.clone(),
        scopes: code.scopes.clone(),
        code_challenge: code.code_challenge.clone(),
        code_challenge_method: code.code_challenge_method.clone(),
        nonce: code.nonce.clone(),
        sid: code.sid.clone(),
        auth_time: code.auth_time,
        expires_at: code.expires_at,
        used: code.used,
        created_at: code.created_at,
    }
}

fn clone_refresh_token(token: &RefreshToken) -> RefreshToken {
    RefreshToken {
        id: token.id,
        client_id: token.client_id,
        user_id: token.user_id,
        refresh_token: token.refresh_token.clone(),
        scopes: token.scopes.clone(),
        auth_time: token.auth_time,
        expires_at: token.expires_at,
        revoked: token.revoked,
        created_at: token.created_at,
        family_id: token.family_id,
    }
}

#[async_trait]
impl AuthorizationCodeStore for MemoryOAuthTokenStore {
    async fn create_auth_code(
        &self,
        params: CreateAuthCodeParams,
    ) -> Result<AuthorizationCode, AppError> {
        let code = AuthorizationCode {
            code: params.code,
            client_id: params.client_id,
            user_id: params.user_id,
            redirect_uri: params.redirect_uri,
            scopes: params.scopes,
            code_challenge: Some(params.code_challenge),
            code_challenge_method: Some(params.code_challenge_method),
            nonce: params.nonce,
            sid: params.sid,
            auth_time: params.auth_time,
            expires_at: Utc::now() + chrono::TimeDelta::minutes(params.ttl_minutes.max(1)),
            used: false,
            created_at: Utc::now(),
        };
        self.auth_codes
            .lock()
            .unwrap()
            .insert(code.code.clone(), clone_auth_code(&code));
        Ok(code)
    }

    async fn find_active_auth_code(
        &self,
        code: &str,
    ) -> Result<Option<AuthorizationCode>, AppError> {
        Ok(self
            .auth_codes
            .lock()
            .unwrap()
            .get(code)
            .filter(|stored| !stored.used && stored.expires_at > Utc::now())
            .map(clone_auth_code))
    }

    async fn consume_auth_code(&self, code: &str) -> Result<bool, AppError> {
        Ok(self.auth_codes.lock().unwrap().remove(code).is_some())
    }

    async fn purge_expired_auth_codes(&self) -> Result<u64, AppError> {
        Ok(0)
    }
}

#[async_trait]
impl RefreshTokenStore for MemoryOAuthTokenStore {
    async fn create_refresh_token(
        &self,
        client_id: Uuid,
        user_id: Uuid,
        refresh_token: &str,
        scopes: &[String],
        auth_time: i64,
        ttl_days: i64,
        family_id: Option<Uuid>,
    ) -> Result<RefreshToken, AppError> {
        let token = RefreshToken {
            id: Uuid::new_v4(),
            client_id,
            user_id,
            refresh_token: refresh_token.into(),
            scopes: scopes.to_vec(),
            auth_time,
            expires_at: Utc::now() + chrono::TimeDelta::days(ttl_days.max(1)),
            revoked: false,
            created_at: Utc::now(),
            family_id,
        };
        self.active_refresh
            .lock()
            .unwrap()
            .insert(token.refresh_token.clone(), clone_refresh_token(&token));
        Ok(token)
    }
    async fn find_active_refresh_for_update(
        &self,
        refresh_token: &str,
    ) -> Result<Option<RefreshToken>, AppError> {
        Ok(self
            .active_refresh
            .lock()
            .unwrap()
            .get(refresh_token)
            .filter(|stored| !stored.revoked && stored.expires_at > Utc::now())
            .map(clone_refresh_token))
    }
    async fn revoke_refresh(&self, id: Uuid) -> Result<(), AppError> {
        let token = self
            .active_refresh
            .lock()
            .unwrap()
            .values()
            .find(|token| token.id == id)
            .map(clone_refresh_token);
        if let Some(mut token) = token {
            self.active_refresh
                .lock()
                .unwrap()
                .remove(&token.refresh_token);
            token.revoked = true;
            self.revoked_refresh
                .lock()
                .unwrap()
                .insert(token.refresh_token.clone(), token);
        }
        Ok(())
    }
    async fn find_revoked_by_token(
        &self,
        refresh_token: &str,
    ) -> Result<Option<RefreshToken>, AppError> {
        Ok(self
            .revoked_refresh
            .lock()
            .unwrap()
            .get(refresh_token)
            .map(clone_refresh_token))
    }
    async fn revoke_all_for_user_client(
        &self,
        user_id: Uuid,
        _client_id: Uuid,
    ) -> Result<(), AppError> {
        self.revoked_users.lock().unwrap().insert(user_id);
        Ok(())
    }
    async fn revoke_all_for_user(&self, user_id: Uuid) -> Result<(), AppError> {
        self.revoked_users.lock().unwrap().insert(user_id);
        Ok(())
    }
    async fn list_active_by_user(
        &self,
        _user_id: Uuid,
    ) -> Result<Vec<pero::domain::oauth::entity::UserAuthorization>, AppError> {
        Ok(vec![])
    }
    async fn revoke_for_user(&self, _id: Uuid, _user_id: Uuid) -> Result<(), AppError> {
        Ok(())
    }
    async fn exchange_auth_code(
        &self,
        code: &str,
        client_id: Uuid,
        _user_id: Uuid,
        _scopes: &[String],
        _auth_time: i64,
        refresh_ttl_days: i64,
    ) -> Result<(AuthorizationCode, Option<String>), AppError> {
        let Some(auth_code) = self.auth_codes.lock().unwrap().remove(code) else {
            return Err(AppError::BadRequest("auth code not found".into()));
        };
        let family_id = Uuid::new_v4();
        let refresh = format!("refresh_{}", Uuid::new_v4().simple());
        self.create_refresh_token(
            client_id,
            auth_code.user_id,
            &refresh,
            &auth_code.scopes,
            auth_code.auth_time,
            refresh_ttl_days,
            Some(family_id),
        )
        .await?;
        Ok((auth_code, Some(refresh)))
    }
    async fn rotate_refresh_token(
        &self,
        old_token: &str,
        client_id: Uuid,
        user_id: Uuid,
        scopes: &[String],
        auth_time: i64,
        ttl_days: i64,
        family_id: Option<Uuid>,
    ) -> Result<(RefreshToken, Option<String>), AppError> {
        let old = self.active_refresh.lock().unwrap().remove(old_token);
        if let Some(mut old) = old {
            old.revoked = true;
            self.revoked_refresh
                .lock()
                .unwrap()
                .insert(old.refresh_token.clone(), old);
        }
        let new_refresh = format!("refresh_{}", Uuid::new_v4().simple());
        let stored = self
            .create_refresh_token(
                client_id,
                user_id,
                &new_refresh,
                scopes,
                auth_time,
                ttl_days,
                family_id,
            )
            .await?;
        Ok((stored, Some(new_refresh)))
    }
    async fn revoke_token_if_owned(&self, token: &str, client_id: Uuid) -> Result<(), AppError> {
        let refresh = self
            .active_refresh
            .lock()
            .unwrap()
            .get(token)
            .filter(|stored| stored.client_id == client_id)
            .map(clone_refresh_token);
        if let Some(mut refresh) = refresh {
            self.active_refresh.lock().unwrap().remove(token);
            refresh.revoked = true;
            self.revoked_refresh
                .lock()
                .unwrap()
                .insert(token.into(), refresh);
            self.revoked_owned.lock().unwrap().insert(token.into());
        }
        Ok(())
    }
    async fn purge_expired_tokens(&self) -> Result<u64, AppError> {
        Ok(0)
    }
}

#[async_trait]
impl TokenFamilyStore for MemoryOAuthTokenStore {
    async fn create_token_family(
        &self,
        client_id: Uuid,
        user_id: Uuid,
    ) -> Result<TokenFamily, AppError> {
        Ok(TokenFamily {
            id: Uuid::new_v4(),
            client_id,
            user_id,
            revoked: false,
            created_at: Utc::now(),
        })
    }

    async fn revoke_token_family(&self, family_id: Uuid) -> Result<(), AppError> {
        self.revoked_families.lock().unwrap().insert(family_id);
        Ok(())
    }
}

#[derive(Default)]
pub struct MemoryKvStore {
    values: Mutex<HashMap<String, Value>>,
}

#[async_trait]
impl KvStore for MemoryKvStore {
    async fn get_raw(&self, key: &str) -> Result<Option<Value>, AppError> {
        Ok(self.values.lock().unwrap().get(key).cloned())
    }

    async fn set_raw(&self, key: &str, value: Value, _ttl: i64) -> Result<(), AppError> {
        self.values.lock().unwrap().insert(key.into(), value);
        Ok(())
    }

    async fn del(&self, key: &str) -> Result<(), AppError> {
        self.values.lock().unwrap().remove(key);
        Ok(())
    }
}

#[derive(Default)]
pub struct MemoryAppStore {
    apps: Mutex<HashMap<Uuid, App>>,
}

impl MemoryAppStore {
    fn app_from_request(req: &CreateAppRequest) -> App {
        let now = Utc::now();
        App {
            id: Uuid::new_v4(),
            name: req.name.clone(),
            code: req.code.clone(),
            description: req.description.clone(),
            enabled: true,
            created_at: now,
            updated_at: now,
        }
    }
}

#[async_trait]
impl AppStore for MemoryAppStore {
    async fn create(&self, req: &CreateAppRequest) -> Result<App, AppError> {
        let app = Self::app_from_request(req);
        self.apps.lock().unwrap().insert(app.id, app.clone());
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
        let mut apps: Vec<_> = self.apps.lock().unwrap().values().cloned().collect();
        apps.sort_by(|a, b| a.code.cmp(&b.code));
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
        if let FieldUpdate::Set(value) = &req.name {
            app.name = value.clone();
        }
        match &req.description {
            FieldUpdate::Set(value) => app.description = Some(value.clone()),
            FieldUpdate::Clear => app.description = None,
            FieldUpdate::Unchanged => {}
        }
        if let FieldUpdate::Set(value) = req.enabled {
            app.enabled = value;
        }
        app.updated_at = Utc::now();
        Ok(app.clone())
    }

    async fn delete(&self, id: Uuid) -> Result<(), AppError> {
        self.apps.lock().unwrap().remove(&id);
        Ok(())
    }
}

#[derive(Default)]
pub struct MemoryOAuth2ClientStore {
    clients: Mutex<HashMap<Uuid, OAuth2Client>>,
}

#[async_trait]
impl OAuth2ClientStore for MemoryOAuth2ClientStore {
    async fn create(
        &self,
        client_id: &str,
        client_secret_hash: &str,
        req: &CreateClientRequest,
    ) -> Result<OAuth2Client, AppError> {
        let now = Utc::now();
        let client = OAuth2Client {
            id: Uuid::new_v4(),
            app_id: req.app_id,
            client_id: client_id.into(),
            client_secret_hash: client_secret_hash.into(),
            client_name: req.client_name.clone(),
            redirect_uris: req.redirect_uris.clone(),
            grant_types: req.grant_types.clone(),
            scopes: req.scopes.clone(),
            post_logout_redirect_uris: req.post_logout_redirect_uris.clone(),
            enabled: true,
            created_at: now,
            updated_at: now,
        };
        self.clients
            .lock()
            .unwrap()
            .insert(client.id, client.clone());
        Ok(client)
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<OAuth2Client>, AppError> {
        Ok(self.clients.lock().unwrap().get(&id).cloned())
    }

    async fn find_by_client_id(&self, client_id: &str) -> Result<Option<OAuth2Client>, AppError> {
        Ok(self
            .clients
            .lock()
            .unwrap()
            .values()
            .find(|client| client.client_id == client_id)
            .cloned())
    }

    async fn list(&self, page: i64, page_size: i64) -> Result<(Vec<OAuth2Client>, i64), AppError> {
        let mut clients: Vec<_> = self.clients.lock().unwrap().values().cloned().collect();
        clients.sort_by(|a, b| a.client_name.cmp(&b.client_name));
        let total = clients.len() as i64;
        let start = ((page.max(1) - 1) * page_size.max(1)) as usize;
        let end = (start + page_size.max(1) as usize).min(clients.len());
        Ok((clients.get(start..end).unwrap_or(&[]).to_vec(), total))
    }

    async fn update(&self, id: Uuid, req: &UpdateClientRequest) -> Result<OAuth2Client, AppError> {
        let mut clients = self.clients.lock().unwrap();
        let client = clients
            .get_mut(&id)
            .ok_or_else(|| AppError::NotFound("client".into()))?;
        if let FieldUpdate::Set(value) = &req.client_name {
            client.client_name = value.clone();
        }
        if let FieldUpdate::Set(value) = &req.redirect_uris {
            client.redirect_uris = value.clone();
        }
        if let FieldUpdate::Set(value) = &req.grant_types {
            client.grant_types = value.clone();
        }
        if let FieldUpdate::Set(value) = &req.scopes {
            client.scopes = value.clone();
        }
        match &req.post_logout_redirect_uris {
            FieldUpdate::Set(value) => client.post_logout_redirect_uris = value.clone(),
            FieldUpdate::Clear => client.post_logout_redirect_uris.clear(),
            FieldUpdate::Unchanged => {}
        }
        if let FieldUpdate::Set(value) = req.enabled {
            client.enabled = value;
        }
        client.updated_at = Utc::now();
        Ok(client.clone())
    }

    async fn delete(&self, id: Uuid) -> Result<(), AppError> {
        self.clients.lock().unwrap().remove(&id);
        Ok(())
    }
}

#[derive(Default)]
pub struct MemorySocialStore {
    providers: Mutex<HashMap<Uuid, SocialProvider>>,
}

#[async_trait]
impl SocialStore for MemorySocialStore {
    async fn create_provider(
        &self,
        req: &CreateSocialProviderRequest,
    ) -> Result<SocialProvider, AppError> {
        let now = Utc::now();
        let provider = SocialProvider {
            id: Uuid::new_v4(),
            name: req.name.clone(),
            display_name: req.display_name.clone(),
            client_id: req.client_id.clone(),
            client_secret: req.client_secret.clone(),
            authorize_url: req.authorize_url.clone(),
            token_url: req.token_url.clone(),
            userinfo_url: req.userinfo_url.clone(),
            scopes: req.scopes.clone(),
            enabled: true,
            created_at: now,
            updated_at: now,
        };
        self.providers
            .lock()
            .unwrap()
            .insert(provider.id, provider.clone());
        Ok(provider)
    }

    async fn find_provider_by_name(&self, name: &str) -> Result<Option<SocialProvider>, AppError> {
        Ok(self
            .providers
            .lock()
            .unwrap()
            .values()
            .find(|provider| provider.name == name)
            .cloned())
    }

    async fn find_provider_by_id(&self, id: Uuid) -> Result<Option<SocialProvider>, AppError> {
        Ok(self.providers.lock().unwrap().get(&id).cloned())
    }

    async fn find_enabled_provider_by_name(
        &self,
        name: &str,
    ) -> Result<Option<SocialProvider>, AppError> {
        Ok(self
            .providers
            .lock()
            .unwrap()
            .values()
            .find(|provider| provider.name == name && provider.enabled)
            .cloned())
    }

    async fn list_enabled_providers(&self) -> Result<Vec<SocialProvider>, AppError> {
        Ok(self
            .providers
            .lock()
            .unwrap()
            .values()
            .filter(|provider| provider.enabled)
            .cloned()
            .collect())
    }

    async fn list_all_providers(&self) -> Result<Vec<SocialProvider>, AppError> {
        Ok(self.providers.lock().unwrap().values().cloned().collect())
    }

    async fn update_provider(
        &self,
        id: Uuid,
        req: &UpdateSocialProviderRequest,
    ) -> Result<SocialProvider, AppError> {
        let mut providers = self.providers.lock().unwrap();
        let provider = providers
            .get_mut(&id)
            .ok_or_else(|| AppError::NotFound("provider".into()))?;
        if let FieldUpdate::Set(value) = &req.display_name {
            provider.display_name = value.clone();
        }
        if let FieldUpdate::Set(value) = &req.client_id {
            provider.client_id = value.clone();
        }
        if let FieldUpdate::Set(value) = &req.client_secret {
            provider.client_secret = value.clone();
        }
        if let FieldUpdate::Set(value) = &req.authorize_url {
            provider.authorize_url = value.clone();
        }
        if let FieldUpdate::Set(value) = &req.token_url {
            provider.token_url = value.clone();
        }
        if let FieldUpdate::Set(value) = &req.userinfo_url {
            provider.userinfo_url = value.clone();
        }
        if let FieldUpdate::Set(value) = &req.scopes {
            provider.scopes = value.clone();
        }
        if let FieldUpdate::Set(value) = req.enabled {
            provider.enabled = value;
        }
        provider.updated_at = Utc::now();
        Ok(provider.clone())
    }

    async fn delete_provider(&self, id: Uuid) -> Result<(), AppError> {
        self.providers.lock().unwrap().remove(&id);
        Ok(())
    }
}

#[derive(Default)]
pub struct MemoryAbacStore {
    policies: Mutex<HashMap<Uuid, pero::domain::abac::models::Policy>>,
    conditions: Mutex<HashMap<Uuid, Vec<pero::domain::abac::models::PolicyCondition>>>,
    assignments: Mutex<HashSet<(Uuid, Uuid)>>,
    subject_attrs: Mutex<HashMap<Uuid, HashMap<String, Vec<String>>>>,
    policy_cache: Mutex<HashMap<(Uuid, Option<Uuid>), AttachedPolicies>>,
}

#[async_trait]
impl AbacStore for MemoryAbacStore {
    async fn create_policy(
        &self,
        req: &pero::domain::abac::models::CreatePolicyRequest,
    ) -> Result<
        (
            pero::domain::abac::models::Policy,
            Vec<pero::domain::abac::models::PolicyCondition>,
        ),
        AppError,
    > {
        let now = Utc::now();
        let policy = pero::domain::abac::models::Policy {
            id: Uuid::new_v4(),
            name: req.name.clone(),
            description: req.description.clone(),
            effect: req.effect.as_str().into(),
            priority: req.priority,
            enabled: req.enabled,
            app_id: req.app_id,
            created_at: now,
            updated_at: now,
        };
        let conditions = req
            .conditions
            .iter()
            .map(|condition| pero::domain::abac::models::PolicyCondition {
                id: Uuid::new_v4(),
                policy_id: policy.id,
                condition_type: condition.condition_type.as_str().into(),
                key: condition.key.clone(),
                operator: condition.operator.as_str().into(),
                value: condition.value.clone(),
            })
            .collect::<Vec<_>>();
        self.policies
            .lock()
            .unwrap()
            .insert(policy.id, policy.clone());
        self.conditions
            .lock()
            .unwrap()
            .insert(policy.id, conditions.clone());
        Ok((policy, conditions))
    }

    async fn find_policy_by_id(
        &self,
        id: Uuid,
    ) -> Result<Option<pero::domain::abac::models::Policy>, AppError> {
        Ok(self.policies.lock().unwrap().get(&id).cloned())
    }

    async fn list_policies(
        &self,
        page: i64,
        page_size: i64,
    ) -> Result<(Vec<pero::domain::abac::models::Policy>, i64), AppError> {
        let mut policies: Vec<_> = self.policies.lock().unwrap().values().cloned().collect();
        policies.sort_by(|a, b| a.name.cmp(&b.name));
        let total = policies.len() as i64;
        let start = ((page.max(1) - 1) * page_size.max(1)) as usize;
        let end = (start + page_size.max(1) as usize).min(policies.len());
        Ok((policies.get(start..end).unwrap_or(&[]).to_vec(), total))
    }

    async fn list_policies_by_app(
        &self,
        app_id: Uuid,
        page: i64,
        page_size: i64,
    ) -> Result<(Vec<pero::domain::abac::models::Policy>, i64), AppError> {
        let (policies, _) = self.list_policies(1, i64::MAX).await?;
        let filtered: Vec<_> = policies
            .into_iter()
            .filter(|policy| policy.app_id == Some(app_id))
            .collect();
        let total = filtered.len() as i64;
        let start = ((page.max(1) - 1) * page_size.max(1)) as usize;
        let end = (start + page_size.max(1) as usize).min(filtered.len());
        Ok((filtered.get(start..end).unwrap_or(&[]).to_vec(), total))
    }

    async fn update_policy(
        &self,
        id: Uuid,
        req: &pero::domain::abac::models::UpdatePolicyRequest,
        policy: &pero::domain::abac::models::Policy,
    ) -> Result<
        (
            pero::domain::abac::models::Policy,
            Vec<pero::domain::abac::models::PolicyCondition>,
        ),
        AppError,
    > {
        let mut updated = policy.clone();
        if let FieldUpdate::Set(value) = &req.name {
            updated.name = value.clone();
        }
        match &req.description {
            FieldUpdate::Set(value) => updated.description = Some(value.clone()),
            FieldUpdate::Clear => updated.description = None,
            FieldUpdate::Unchanged => {}
        }
        if let FieldUpdate::Set(value) = &req.effect {
            updated.effect = value.as_str().into();
        }
        if let FieldUpdate::Set(value) = req.priority {
            updated.priority = value;
        }
        if let FieldUpdate::Set(value) = req.enabled {
            updated.enabled = value;
        }
        match req.app_id {
            FieldUpdate::Set(value) => updated.app_id = Some(value),
            FieldUpdate::Clear => updated.app_id = None,
            FieldUpdate::Unchanged => {}
        }
        updated.updated_at = Utc::now();
        let conditions = if let FieldUpdate::Set(items) = &req.conditions {
            items
                .iter()
                .map(|condition| pero::domain::abac::models::PolicyCondition {
                    id: Uuid::new_v4(),
                    policy_id: id,
                    condition_type: condition.condition_type.as_str().into(),
                    key: condition.key.clone(),
                    operator: condition.operator.as_str().into(),
                    value: condition.value.clone(),
                })
                .collect()
        } else {
            self.conditions
                .lock()
                .unwrap()
                .get(&id)
                .cloned()
                .unwrap_or_default()
        };
        self.policies.lock().unwrap().insert(id, updated.clone());
        self.conditions
            .lock()
            .unwrap()
            .insert(id, conditions.clone());
        Ok((updated, conditions))
    }

    async fn delete_policy(&self, id: Uuid) -> Result<(), AppError> {
        self.policies.lock().unwrap().remove(&id);
        self.conditions.lock().unwrap().remove(&id);
        self.assignments
            .lock()
            .unwrap()
            .retain(|(_, policy_id)| *policy_id != id);
        Ok(())
    }

    async fn select_policies(
        &self,
        filter: PolicyFilter,
    ) -> Result<Vec<pero::domain::abac::models::Policy>, AppError> {
        let assignments = self.assignments.lock().unwrap().clone();
        Ok(self
            .policies
            .lock()
            .unwrap()
            .values()
            .filter(|policy| !filter.enabled_only || policy.enabled)
            .filter(|policy| {
                filter
                    .app_id
                    .is_none_or(|app_id| policy.app_id.is_none() || policy.app_id == Some(app_id))
            })
            .filter(|policy| {
                filter
                    .user_id
                    .is_none_or(|user_id| assignments.contains(&(user_id, policy.id)))
            })
            .cloned()
            .collect())
    }

    async fn attach_conditions(
        &self,
        policies: Vec<pero::domain::abac::models::Policy>,
    ) -> Result<
        Vec<(
            pero::domain::abac::models::Policy,
            Vec<pero::domain::abac::models::PolicyCondition>,
        )>,
        AppError,
    > {
        let conditions = self.conditions.lock().unwrap();
        Ok(policies
            .into_iter()
            .map(|policy| {
                let items = conditions.get(&policy.id).cloned().unwrap_or_default();
                (policy, items)
            })
            .collect())
    }

    async fn load_user_attributes(&self, user_id: Uuid) -> Result<Vec<(String, String)>, AppError> {
        Ok(self
            .subject_attrs
            .lock()
            .unwrap()
            .get(&user_id)
            .map(|attrs| {
                attrs
                    .iter()
                    .flat_map(|(key, values)| {
                        values
                            .iter()
                            .map(|value| (key.clone(), value.clone()))
                            .collect::<Vec<_>>()
                    })
                    .collect()
            })
            .unwrap_or_default())
    }

    async fn assign_policy(&self, user_id: Uuid, policy_id: Uuid) -> Result<(), AppError> {
        self.assignments
            .lock()
            .unwrap()
            .insert((user_id, policy_id));
        Ok(())
    }

    async fn unassign_policy(&self, user_id: Uuid, policy_id: Uuid) -> Result<(), AppError> {
        self.assignments
            .lock()
            .unwrap()
            .remove(&(user_id, policy_id));
        Ok(())
    }
}

#[async_trait]
impl AbacCacheStore for MemoryAbacStore {
    async fn get_subject_attrs(
        &self,
        user_id: Uuid,
    ) -> Result<Option<HashMap<String, Vec<String>>>, AppError> {
        Ok(self.subject_attrs.lock().unwrap().get(&user_id).cloned())
    }

    async fn set_subject_attrs(
        &self,
        user_id: Uuid,
        attrs: &HashMap<String, Vec<String>>,
        _ttl: i64,
    ) -> Result<(), AppError> {
        self.subject_attrs
            .lock()
            .unwrap()
            .insert(user_id, attrs.clone());
        Ok(())
    }

    async fn get_policies(
        &self,
        user_id: Uuid,
        app_id: Option<Uuid>,
    ) -> Result<Option<AttachedPolicies>, AppError> {
        Ok(self
            .policy_cache
            .lock()
            .unwrap()
            .get(&(user_id, app_id))
            .cloned())
    }

    async fn set_policies(
        &self,
        user_id: Uuid,
        app_id: Option<Uuid>,
        policies: &AttachedPolicies,
        _ttl: i64,
    ) -> Result<(), AppError> {
        self.policy_cache
            .lock()
            .unwrap()
            .insert((user_id, app_id), policies.clone());
        Ok(())
    }

    async fn get_app_policy_version(
        &self,
        _app_id: Option<Uuid>,
    ) -> Result<Option<String>, AppError> {
        Ok(None)
    }

    async fn bump_app_policy_version(
        &self,
        _app_id: Option<Uuid>,
        _ttl: i64,
    ) -> Result<(), AppError> {
        self.policy_cache.lock().unwrap().clear();
        Ok(())
    }

    async fn get_user_version(&self, _user_id: Uuid) -> Result<Option<String>, AppError> {
        Ok(None)
    }

    async fn bump_user_version(&self, user_id: Uuid, _ttl: i64) -> Result<(), AppError> {
        self.subject_attrs.lock().unwrap().remove(&user_id);
        Ok(())
    }
}

#[derive(Default)]
pub struct NoopStore;

#[async_trait]
impl AppStore for NoopStore {
    async fn create(&self, _req: &CreateAppRequest) -> Result<App, AppError> {
        Err(AppError::BadRequest("unused".into()))
    }
    async fn find_by_id(&self, _id: Uuid) -> Result<Option<App>, AppError> {
        Ok(None)
    }
    async fn find_by_code(&self, _code: &str) -> Result<Option<App>, AppError> {
        Ok(None)
    }
    async fn list(&self, _page: i64, _page_size: i64) -> Result<(Vec<App>, i64), AppError> {
        Ok((vec![], 0))
    }
    async fn update(&self, _id: Uuid, _req: &UpdateAppRequest) -> Result<App, AppError> {
        Err(AppError::BadRequest("unused".into()))
    }
    async fn delete(&self, _id: Uuid) -> Result<(), AppError> {
        Ok(())
    }
}

#[async_trait]
impl OAuth2ClientStore for NoopStore {
    async fn create(
        &self,
        _client_id: &str,
        _client_secret_hash: &str,
        _req: &CreateClientRequest,
    ) -> Result<OAuth2Client, AppError> {
        Err(AppError::BadRequest("unused".into()))
    }
    async fn find_by_id(&self, _id: Uuid) -> Result<Option<OAuth2Client>, AppError> {
        Ok(None)
    }
    async fn find_by_client_id(&self, _client_id: &str) -> Result<Option<OAuth2Client>, AppError> {
        Ok(None)
    }
    async fn list(
        &self,
        _page: i64,
        _page_size: i64,
    ) -> Result<(Vec<OAuth2Client>, i64), AppError> {
        Ok((vec![], 0))
    }
    async fn update(
        &self,
        _id: Uuid,
        _req: &UpdateClientRequest,
    ) -> Result<OAuth2Client, AppError> {
        Err(AppError::BadRequest("unused".into()))
    }
    async fn delete(&self, _id: Uuid) -> Result<(), AppError> {
        Ok(())
    }
}

impl TokenSigner for NoopStore {
    fn sign_access_token(&self, params: AccessTokenParams) -> Result<String, AppError> {
        Ok(format!("access:{}", params.sub))
    }
    fn sign_id_token(
        &self,
        sub: String,
        _iss: String,
        _aud: String,
        _exp: i64,
        _iat: i64,
        _auth_time: i64,
        _nonce: Option<String>,
        _name: Option<String>,
        _nickname: Option<String>,
        _picture: Option<String>,
        _email: Option<String>,
        _email_verified: Option<bool>,
        _phone_number: Option<String>,
        _phone_number_verified: Option<bool>,
        _sid: Option<String>,
    ) -> Result<String, AppError> {
        Ok(format!("id:{sub}"))
    }
    fn issuer(&self) -> &str {
        "https://auth.test"
    }
}

#[async_trait]
impl AbacStore for NoopStore {
    async fn create_policy(
        &self,
        _req: &pero::domain::abac::models::CreatePolicyRequest,
    ) -> Result<
        (
            pero::domain::abac::models::Policy,
            Vec<pero::domain::abac::models::PolicyCondition>,
        ),
        AppError,
    > {
        Err(AppError::BadRequest("unused".into()))
    }
    async fn find_policy_by_id(
        &self,
        _id: Uuid,
    ) -> Result<Option<pero::domain::abac::models::Policy>, AppError> {
        Ok(None)
    }
    async fn list_policies(
        &self,
        _page: i64,
        _page_size: i64,
    ) -> Result<(Vec<pero::domain::abac::models::Policy>, i64), AppError> {
        Ok((vec![], 0))
    }
    async fn list_policies_by_app(
        &self,
        _app_id: Uuid,
        _page: i64,
        _page_size: i64,
    ) -> Result<(Vec<pero::domain::abac::models::Policy>, i64), AppError> {
        Ok((vec![], 0))
    }
    async fn update_policy(
        &self,
        _id: Uuid,
        _req: &pero::domain::abac::models::UpdatePolicyRequest,
        _policy: &pero::domain::abac::models::Policy,
    ) -> Result<
        (
            pero::domain::abac::models::Policy,
            Vec<pero::domain::abac::models::PolicyCondition>,
        ),
        AppError,
    > {
        Err(AppError::BadRequest("unused".into()))
    }
    async fn delete_policy(&self, _id: Uuid) -> Result<(), AppError> {
        Ok(())
    }
    async fn select_policies(
        &self,
        _filter: PolicyFilter,
    ) -> Result<Vec<pero::domain::abac::models::Policy>, AppError> {
        Ok(vec![])
    }
    async fn attach_conditions(
        &self,
        policies: Vec<pero::domain::abac::models::Policy>,
    ) -> Result<
        Vec<(
            pero::domain::abac::models::Policy,
            Vec<pero::domain::abac::models::PolicyCondition>,
        )>,
        AppError,
    > {
        Ok(policies.into_iter().map(|p| (p, vec![])).collect())
    }
    async fn load_user_attributes(
        &self,
        _user_id: Uuid,
    ) -> Result<Vec<(String, String)>, AppError> {
        Ok(vec![])
    }
    async fn assign_policy(&self, _user_id: Uuid, _policy_id: Uuid) -> Result<(), AppError> {
        Ok(())
    }
    async fn unassign_policy(&self, _user_id: Uuid, _policy_id: Uuid) -> Result<(), AppError> {
        Ok(())
    }
}

#[async_trait]
impl AbacCacheStore for NoopStore {
    async fn get_subject_attrs(
        &self,
        _user_id: Uuid,
    ) -> Result<Option<HashMap<String, Vec<String>>>, AppError> {
        Ok(None)
    }
    async fn set_subject_attrs(
        &self,
        _user_id: Uuid,
        _attrs: &HashMap<String, Vec<String>>,
        _ttl: i64,
    ) -> Result<(), AppError> {
        Ok(())
    }
    async fn get_policies(
        &self,
        _user_id: Uuid,
        _app_id: Option<Uuid>,
    ) -> Result<Option<AttachedPolicies>, AppError> {
        Ok(None)
    }
    async fn set_policies(
        &self,
        _user_id: Uuid,
        _app_id: Option<Uuid>,
        _policies: &AttachedPolicies,
        _ttl: i64,
    ) -> Result<(), AppError> {
        Ok(())
    }
    async fn get_app_policy_version(
        &self,
        _app_id: Option<Uuid>,
    ) -> Result<Option<String>, AppError> {
        Ok(None)
    }
    async fn bump_app_policy_version(
        &self,
        _app_id: Option<Uuid>,
        _ttl: i64,
    ) -> Result<(), AppError> {
        Ok(())
    }
    async fn get_user_version(&self, _user_id: Uuid) -> Result<Option<String>, AppError> {
        Ok(None)
    }
    async fn bump_user_version(&self, _user_id: Uuid, _ttl: i64) -> Result<(), AppError> {
        Ok(())
    }
}

#[async_trait]
impl SocialStore for NoopStore {
    async fn create_provider(
        &self,
        _req: &CreateSocialProviderRequest,
    ) -> Result<SocialProvider, AppError> {
        Err(AppError::BadRequest("unused".into()))
    }
    async fn find_provider_by_name(&self, _name: &str) -> Result<Option<SocialProvider>, AppError> {
        Ok(None)
    }
    async fn find_provider_by_id(&self, _id: Uuid) -> Result<Option<SocialProvider>, AppError> {
        Ok(None)
    }
    async fn find_enabled_provider_by_name(
        &self,
        _name: &str,
    ) -> Result<Option<SocialProvider>, AppError> {
        Ok(None)
    }
    async fn list_enabled_providers(&self) -> Result<Vec<SocialProvider>, AppError> {
        Ok(vec![])
    }
    async fn list_all_providers(&self) -> Result<Vec<SocialProvider>, AppError> {
        Ok(vec![])
    }
    async fn update_provider(
        &self,
        _id: Uuid,
        _req: &UpdateSocialProviderRequest,
    ) -> Result<SocialProvider, AppError> {
        Err(AppError::BadRequest("unused".into()))
    }
    async fn delete_provider(&self, _id: Uuid) -> Result<(), AppError> {
        Ok(())
    }
}

#[async_trait]
impl HttpClient for NoopStore {
    async fn post_form(&self, _url: &str, _fields: Vec<(&str, &str)>) -> Result<Value, AppError> {
        Err(AppError::BadRequest("unused".into()))
    }
    async fn get_bearer(&self, _url: &str, _access_token: &str) -> Result<Value, AppError> {
        Err(AppError::BadRequest("unused".into()))
    }
}
