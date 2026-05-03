use chrono::Utc;
use redis::AsyncCommands;
use uuid::Uuid;

use crate::domain::identity::repo::SessionStore;
use crate::domain::identity::session::IdentitySession;
use crate::infra::cache;
use crate::shared::cache_keys::identity_session::{session_key, user_sessions_key};
use crate::shared::constants::cache_keys;
use crate::shared::error::AppError;
use crate::shared::utils;

const SECONDS_PER_DAY: i64 = 86_400;

pub struct RedisSessionStore {
    pool: cache::Pool,
}

impl RedisSessionStore {
    pub fn new(pool: cache::Pool) -> Self {
        Self { pool }
    }
}

fn hash_refresh_token(refresh_token: &str) -> String {
    utils::sha256_hex(refresh_token)
}

fn build_refresh_token(session_id: &str) -> String {
    let secret = utils::random_hex_token();
    format!("{session_id}.{secret}")
}

fn ttl_seconds(ttl_days: i64) -> i64 {
    ttl_days * SECONDS_PER_DAY
}

#[async_trait::async_trait]
impl SessionStore for RedisSessionStore {
    async fn create(
        &self,
        user_id: Uuid,
        ttl_days: i64,
        device: &str,
        location: &str,
    ) -> Result<(IdentitySession, String), AppError> {
        let now = Utc::now().timestamp();
        let session_id = Uuid::new_v4().to_string();
        let refresh_token = build_refresh_token(&session_id);
        let session = IdentitySession {
            session_id: session_id.clone(),
            user_id,
            refresh_token_hash: hash_refresh_token(&refresh_token),
            previous_refresh_token_hash: None,
            created_at: now,
            rotated_at: now,
            device: device.to_string(),
            location: location.to_string(),
        };

        cache::set_json(
            &self.pool,
            &session_key(&session_id),
            &session,
            ttl_seconds(ttl_days),
        )
        .await?;

        {
            let mut conn = cache::with_conn(&self.pool).await?;
            let ukey = user_sessions_key(user_id);
            let _: usize = conn.sadd(&ukey, &session_id).await?;
            let _: bool = conn.expire(&ukey, ttl_seconds(ttl_days)).await?;
        }

        Ok((session, refresh_token))
    }

    async fn get(&self, session_id: &str) -> Result<Option<IdentitySession>, AppError> {
        cache::get_json(&self.pool, &session_key(session_id)).await
    }

    async fn rotate(
        &self,
        session_id: &str,
        old_hash: &str,
        new_token: &str,
        ttl_days: i64,
    ) -> Result<bool, AppError> {
        static LUA: std::sync::OnceLock<String> = std::sync::OnceLock::new();
        let lua = LUA.get_or_init(|| {
            format!(
                r#"
                local key = KEYS[1]
                local expected = ARGV[1]
                local next_hash = ARGV[2]
                local ttl = tonumber(ARGV[3])
                local now = tonumber(ARGV[4])
                local payload = redis.call('GET', key)
                if not payload then
                    return 0
                end
                local doc = cjson.decode(payload)
                if doc.refresh_token_hash ~= expected then
                    return 0
                end
                local user_key = '{}' .. doc.user_id
                doc.previous_refresh_token_hash = doc.refresh_token_hash
                doc.refresh_token_hash = next_hash
                doc.rotated_at = now
                redis.call('SET', key, cjson.encode(doc), 'EX', ttl)
                redis.call('SADD', user_key, doc.session_id)
                redis.call('EXPIRE', user_key, ttl)
                return 1
            "#,
                cache_keys::IDENTITY_USER_SESSIONS_PREFIX
            )
        });

        let mut conn = cache::with_conn(&self.pool).await?;
        let ok: i32 = redis::Script::new(lua)
            .key(session_key(session_id))
            .arg(old_hash)
            .arg(hash_refresh_token(new_token))
            .arg(ttl_seconds(ttl_days))
            .arg(Utc::now().timestamp())
            .invoke_async(&mut *conn)
            .await?;
        Ok(ok == 1)
    }

    async fn revoke(&self, session_id: &str) -> Result<(), AppError> {
        let existing = self.get(session_id).await?;
        if let Some(session) = existing {
            cache::del(&self.pool, &session_key(session_id)).await?;
            let mut conn = cache::with_conn(&self.pool).await?;
            let ukey = user_sessions_key(session.user_id);
            let _: usize = conn.srem(&ukey, session_id).await?;
            let remaining: usize = conn.scard(&ukey).await?;
            if remaining == 0 {
                let _: usize = conn.del(&ukey).await?;
            }
        }
        Ok(())
    }

    async fn revoke_all_for_user(&self, user_id: Uuid) -> Result<(), AppError> {
        let index = {
            let mut conn = cache::with_conn(&self.pool).await?;
            let ukey = user_sessions_key(user_id);
            let session_ids: Vec<String> = conn.smembers(&ukey).await?;
            session_ids
        };

        if index.is_empty() {
            cache::del(&self.pool, &user_sessions_key(user_id)).await?;
            return Ok(());
        }

        let mut conn = cache::with_conn(&self.pool).await?;
        let mut pipe = redis::Pipeline::new();
        for sid in &index {
            pipe.del(session_key(sid));
        }
        pipe.del(user_sessions_key(user_id));
        pipe.query_async::<()>(&mut *conn).await?;

        Ok(())
    }

    async fn list_user_session_ids(&self, user_id: Uuid) -> Result<Vec<String>, AppError> {
        let mut conn = cache::with_conn(&self.pool).await?;
        let ukey = user_sessions_key(user_id);
        let session_ids: Vec<String> = conn.smembers(&ukey).await?;
        Ok(session_ids)
    }

    async fn verify(&self, session_id: &str, user_id: Uuid) -> Result<IdentitySession, AppError> {
        let session = self
            .get(session_id)
            .await?
            .ok_or(AppError::Unauthorized)?;
        if session.user_id != user_id {
            return Err(AppError::Unauthorized);
        }
        Ok(session)
    }
}
