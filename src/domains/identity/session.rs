use crate::cache::Pool;
use crate::shared::error::AppError;
use chrono::Utc;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

const SECONDS_PER_DAY: i64 = 86_400;
const IDENTITY_SESSION_PREFIX: &str = "identity_session:";
const IDENTITY_USER_SESSIONS_PREFIX: &str = "identity_user_sessions:";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentitySession {
    pub session_id: String,
    pub user_id: Uuid,
    pub refresh_token_hash: String,
    pub previous_refresh_token_hash: Option<String>,
    pub created_at: i64,
    pub rotated_at: i64,
}

pub fn parse_session_id(refresh_token: &str) -> Result<&str, AppError> {
    refresh_token
        .split_once('.')
        .map(|(session_id, _)| session_id)
        .ok_or(AppError::Unauthorized)
}

pub fn hash_refresh_token(refresh_token: &str) -> String {
    crate::shared::utils::sha256_hex(refresh_token)
}

pub async fn create_session(
    pool: &Pool,
    user_id: Uuid,
    ttl_days: i64,
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
    };

    store_session(pool, &session, ttl_days).await?;
    add_user_session_index(pool, user_id, &session_id, ttl_days).await?;

    Ok((session, refresh_token))
}

pub async fn get_session(
    pool: &Pool,
    session_id: &str,
) -> Result<Option<IdentitySession>, AppError> {
    crate::cache::get_json(pool, &session_key(session_id)).await
}

pub async fn rotate_refresh_token(
    pool: &Pool,
    session_id: &str,
    expected_old_hash: &str,
    new_refresh_token: &str,
    ttl_days: i64,
) -> Result<bool, AppError> {
    static LUA: &str = r#"
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
        local user_key = 'identity_user_sessions:' .. doc.user_id
        doc.previous_refresh_token_hash = doc.refresh_token_hash
        doc.refresh_token_hash = next_hash
        doc.rotated_at = now
        redis.call('SET', key, cjson.encode(doc), 'EX', ttl)
        redis.call('SADD', user_key, doc.session_id)
        redis.call('EXPIRE', user_key, ttl)
        return 1
    "#;

    let mut conn = pool
        .get()
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let ok: i32 = redis::Script::new(LUA)
        .key(session_key(session_id))
        .arg(expected_old_hash)
        .arg(hash_refresh_token(new_refresh_token))
        .arg(ttl_seconds(ttl_days))
        .arg(Utc::now().timestamp())
        .invoke_async(&mut *conn)
        .await?;
    Ok(ok == 1)
}

pub async fn revoke_session(pool: &Pool, session_id: &str) -> Result<(), AppError> {
    let existing = get_session(pool, session_id).await?;
    if let Some(session) = existing {
        crate::cache::del(pool, &session_key(session_id)).await?;
        remove_user_session_index(pool, session.user_id, session_id).await?;
    }
    Ok(())
}

pub async fn revoke_user_sessions(pool: &Pool, user_id: Uuid) -> Result<(), AppError> {
    let session_ids = get_user_session_ids(pool, user_id).await?;
    for session_id in &session_ids {
        crate::cache::del(pool, &session_key(session_id)).await?;
    }
    delete_user_session_index(pool, user_id).await
}

fn session_key(session_id: &str) -> String {
    format!("{IDENTITY_SESSION_PREFIX}{session_id}")
}

pub fn build_refresh_token(session_id: &str) -> String {
    let secret = crate::shared::utils::random_hex_token();
    format!("{session_id}.{secret}")
}

fn user_sessions_key(user_id: Uuid) -> String {
    format!("{IDENTITY_USER_SESSIONS_PREFIX}{user_id}")
}

fn ttl_seconds(ttl_days: i64) -> i64 {
    ttl_days * SECONDS_PER_DAY
}

async fn store_session(
    pool: &Pool,
    session: &IdentitySession,
    ttl_days: i64,
) -> Result<(), AppError> {
    crate::cache::set_json(
        pool,
        &session_key(&session.session_id),
        session,
        ttl_seconds(ttl_days),
    )
    .await
}

async fn add_user_session_index(
    pool: &Pool,
    user_id: Uuid,
    session_id: &str,
    ttl_days: i64,
) -> Result<(), AppError> {
    let mut conn = pool
        .get()
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let key = user_sessions_key(user_id);
    let _: usize = conn.sadd(&key, session_id).await?;
    let _: bool = conn.expire(&key, ttl_seconds(ttl_days)).await?;
    Ok(())
}

async fn remove_user_session_index(
    pool: &Pool,
    user_id: Uuid,
    session_id: &str,
) -> Result<(), AppError> {
    let mut conn = pool
        .get()
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let key = user_sessions_key(user_id);
    let _: usize = conn.srem(&key, session_id).await?;
    let remaining: usize = conn.scard(&key).await?;
    if remaining == 0 {
        let _: usize = conn.del(&key).await?;
    }
    Ok(())
}

async fn get_user_session_ids(pool: &Pool, user_id: Uuid) -> Result<Vec<String>, AppError> {
    let mut conn = pool
        .get()
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?;
    let key = user_sessions_key(user_id);
    let session_ids: Vec<String> = conn.smembers(&key).await?;
    Ok(session_ids)
}

async fn delete_user_session_index(pool: &Pool, user_id: Uuid) -> Result<(), AppError> {
    crate::cache::del(pool, &user_sessions_key(user_id)).await
}
