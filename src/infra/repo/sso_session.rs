use uuid::Uuid;

use crate::domain::sso::models::SsoSession;
use crate::domain::sso::repo::SsoSessionStore;
use crate::infra::cache;
use crate::shared::cache_keys::sso::session_key;
use crate::shared::error::AppError;

pub struct RedisSsoSessionStore {
    pool: cache::Pool,
}

impl RedisSsoSessionStore {
    pub fn new(pool: cache::Pool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl SsoSessionStore for RedisSsoSessionStore {
    async fn create(&self, session: &SsoSession, ttl_seconds: i64) -> Result<String, AppError> {
        let id = Uuid::new_v4().to_string();
        let key = session_key(&id);
        cache::set_json(&self.pool, &key, session, ttl_seconds).await?;
        Ok(id)
    }

    async fn get(&self, session_id: &str) -> Result<Option<SsoSession>, AppError> {
        let key = session_key(session_id);
        cache::get_json(&self.pool, &key).await
    }

    async fn update(
        &self,
        session_id: &str,
        session: &SsoSession,
        ttl_seconds: i64,
    ) -> Result<(), AppError> {
        let key = session_key(session_id);
        cache::set_json(&self.pool, &key, session, ttl_seconds).await
    }

    async fn delete(&self, session_id: &str) -> Result<(), AppError> {
        let key = session_key(session_id);
        cache::del(&self.pool, &key).await
    }
}
