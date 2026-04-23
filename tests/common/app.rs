use crate::common::cleanup::{
    CleanupItem, cleanup_app, cleanup_client, cleanup_policy, cleanup_user,
};
use pero::config::AppConfig;
use pero::shared::state::AppState;
use sqlx::postgres::PgPool;
use std::sync::{Arc, OnceLock};

type SharedResources = (
    PgPool,
    pero::infra::cache::Pool,
    Arc<AppConfig>,
    Arc<pero::infra::jwt::JwtKeys>,
);

static TEST_RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
static APP_RESOURCES: OnceLock<SharedResources> = OnceLock::new();

pub fn ensure_rt() -> &'static tokio::runtime::Runtime {
    TEST_RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("Failed to create test runtime")
    })
}

fn init_resources() -> SharedResources {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .with_target(false)
        .try_init();

    std::thread::scope(|s| {
        let handle = s.spawn(|| {
            let rt = ensure_rt();
            let _guard = rt.enter();
            rt.block_on(async {
                let cfg = load_test_config().expect("Failed to load test config");
                let jwt_keys =
                    pero::infra::jwt::JwtKeys::load(&cfg.oidc).expect("Failed to load JWT keys");
                let config = Arc::new(cfg);
                let jwt_keys = Arc::new(jwt_keys);

                let db = pero::infra::db::init_pool(&config.database)
                    .await
                    .expect("Failed to init DB");
                let cache = pero::infra::cache::init_pool(&config.redis)
                    .await
                    .expect("Failed to init Redis");

                (db, cache, config, jwt_keys)
            })
        });
        handle.join().expect("init panicked")
    })
}

pub fn shared_resources() -> &'static SharedResources {
    APP_RESOURCES.get_or_init(init_resources)
}

pub async fn build_app() -> TestApp {
    let guard = ensure_rt().enter();
    let (db, cache, config, jwt_keys) = shared_resources();
    let app = pero::api::build_router(AppState {
        db: db.clone(),
        cache: cache.clone(),
        config: config.clone(),
        jwt_keys: jwt_keys.clone(),
        discovery_doc: std::sync::OnceLock::new(),
        jwks_doc: std::sync::OnceLock::new(),
    });

    TestApp {
        app,
        db: db.clone(),
        cache: cache.clone(),
        config: config.clone(),
        cleanup: Vec::new(),
        _guard: guard,
    }
}

pub async fn build_router() -> (axum::Router, tokio::runtime::EnterGuard<'static>) {
    let guard = ensure_rt().enter();
    let (db, cache, config, jwt_keys) = shared_resources();
    let router = pero::api::build_router(AppState {
        db: db.clone(),
        cache: cache.clone(),
        config: config.clone(),
        jwt_keys: jwt_keys.clone(),
        discovery_doc: std::sync::OnceLock::new(),
        jwks_doc: std::sync::OnceLock::new(),
    });
    (router, guard)
}

pub struct TestApp {
    pub app: axum::Router,
    pub db: PgPool,
    pub cache: pero::infra::cache::Pool,
    pub config: Arc<AppConfig>,
    cleanup: Vec<CleanupItem>,
    _guard: tokio::runtime::EnterGuard<'static>,
}

impl Drop for TestApp {
    fn drop(&mut self) {
        if self.cleanup.is_empty() {
            return;
        }
        let db = self.db.clone();
        let items: Vec<CleanupItem> = self.cleanup.drain(..).collect();
        tokio::spawn(async move {
            for item in items {
                match item {
                    CleanupItem::Client(id) => cleanup_client(&db, id).await,
                    CleanupItem::Policy(id) => cleanup_policy(&db, id).await,
                    CleanupItem::App(id) => cleanup_app(&db, id).await,
                    CleanupItem::User(id) => cleanup_user(&db, id).await,
                }
            }
        });
    }
}

impl TestApp {
    pub fn track_user(&mut self, user_id: uuid::Uuid) {
        self.cleanup.push(CleanupItem::User(user_id));
    }

    pub fn track_app(&mut self, app_id: uuid::Uuid) {
        self.cleanup.push(CleanupItem::App(app_id));
    }

    pub fn track_policy(&mut self, policy_id: uuid::Uuid) {
        self.cleanup.push(CleanupItem::Policy(policy_id));
    }

    pub fn track_client(&mut self, client_id: uuid::Uuid) {
        self.cleanup.push(CleanupItem::Client(client_id));
    }

    pub async fn cleanup(mut self) {
        while let Some(item) = self.cleanup.pop() {
            match item {
                CleanupItem::Client(client_id) => cleanup_client(&self.db, client_id).await,
                CleanupItem::Policy(policy_id) => cleanup_policy(&self.db, policy_id).await,
                CleanupItem::App(app_id) => cleanup_app(&self.db, app_id).await,
                CleanupItem::User(user_id) => {
                    self.clear_user_cache(user_id).await;
                    cleanup_user(&self.db, user_id).await;
                }
            }
        }
    }

    pub(crate) async fn clear_user_cache(&self, user_id: uuid::Uuid) {
        use redis::AsyncCommands;

        let mut conn = match self.cache.get().await {
            Ok(c) => c,
            Err(_) => return,
        };

        let identity_index_key = format!("identity_user_sessions:{user_id}");
        if let Ok(session_ids) = conn.smembers::<_, Vec<String>>(&identity_index_key).await {
            for session_id in session_ids {
                let _: Result<(), redis::RedisError> =
                    conn.del(format!("identity_session:{session_id}")).await;
            }
        }
        let _: Result<(), redis::RedisError> = conn.del(&identity_index_key).await;

        for key in [
            format!("refresh_token:{user_id}"),
            format!("abac_subject:{user_id}"),
        ] {
            let _: Result<(), redis::RedisError> = conn.del(&key).await;
        }
    }
}

fn load_test_config() -> Result<AppConfig, config::ConfigError> {
    let cfg = config::Config::builder()
        .add_source(config::File::with_name("config/default"))
        .add_source(config::File::with_name("config/test"))
        .add_source(
            config::Environment::with_prefix("PERO")
                .separator("__")
                .try_parsing(true),
        )
        .build()?;

    cfg.try_deserialize()
}
