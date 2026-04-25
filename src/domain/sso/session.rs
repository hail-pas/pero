use axum::http::HeaderMap;

use crate::domain::sso::models::SsoSession;
use crate::infra::cache;
use crate::infra::cache::Pool;
use crate::shared::constants::cache_keys::SSO_SESSION_PREFIX;
use crate::shared::error::AppError;

pub const COOKIE_NAME: &str = "pero_sso_session";
const COOKIE_PREFIX: &str = "pero_sso_session=";

pub fn get_session_id(headers: &HeaderMap) -> Option<String> {
    headers
        .get(axum::http::header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|cookie| {
            cookie
                .split(';')
                .find_map(|c| {
                    let pair = c.trim();
                    pair.strip_prefix(COOKIE_PREFIX)
                })
                .map(String::from)
        })
}

pub async fn require(pool: &Pool, headers: &HeaderMap) -> Result<(String, SsoSession), AppError> {
    let sid = get_session_id(headers).ok_or(AppError::BadRequest("no session".into()))?;
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
