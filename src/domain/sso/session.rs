use axum::http::HeaderMap;

use crate::domain::sso::models::SsoSession;
use crate::infra::cache;
use crate::infra::cache::Pool;
use crate::shared::constants::cache_keys::SSO_SESSION_PREFIX;
use crate::shared::constants::cookies::SSO_SESSION;
use crate::shared::error::AppError;
use crate::shared::utils::extract_cookie;

pub async fn require(pool: &Pool, headers: &HeaderMap) -> Result<(String, SsoSession), AppError> {
    let sid =
        extract_cookie(headers, SSO_SESSION).ok_or(AppError::BadRequest("no session".into()))?;
    let sso = get(pool, &sid)
        .await?
        .ok_or(AppError::BadRequest("no session".into()))?;
    Ok((sid, sso))
}

pub async fn create(
    pool: &Pool,
    session: &SsoSession,
    ttl_seconds: i64,
) -> Result<String, AppError> {
    let id = uuid::Uuid::new_v4().to_string();
    let key = format!("{}{}", SSO_SESSION_PREFIX, id);
    cache::set_json(pool, &key, session, ttl_seconds).await?;
    Ok(id)
}

pub async fn get(pool: &Pool, session_id: &str) -> Result<Option<SsoSession>, AppError> {
    let key = format!("{}{}", SSO_SESSION_PREFIX, session_id);
    cache::get_json(pool, &key).await
}

pub async fn update(
    pool: &Pool,
    session_id: &str,
    session: &SsoSession,
    ttl_seconds: i64,
) -> Result<(), AppError> {
    let key = format!("{}{}", SSO_SESSION_PREFIX, session_id);
    cache::set_json(pool, &key, session, ttl_seconds).await
}

pub async fn delete(pool: &Pool, session_id: &str) -> Result<(), AppError> {
    let key = format!("{}{}", SSO_SESSION_PREFIX, session_id);
    cache::del(pool, &key).await
}
