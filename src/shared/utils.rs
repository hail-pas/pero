use askama::Template;
use axum::http::HeaderMap;
use axum::response::Html;
use serde::Deserialize;
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::infra::cache::Pool;
use crate::shared::error::AppError;

pub fn parse_user_agent(headers: &HeaderMap) -> (String, String) {
    let ua = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let parser = woothee::parser::Parser::new();
    let result = parser.parse(ua);
    match result {
        Some(w) => {
            let device = if !w.name.is_empty() && !w.os.is_empty() {
                if w.os_version.is_empty() {
                    format!("{}/{}", w.name, w.os)
                } else {
                    format!("{}/{} {}", w.name, w.os, w.os_version)
                }
            } else if !w.name.is_empty() {
                w.name.to_string()
            } else {
                "Unknown".to_string()
            };
            (device, String::new())
        }
        None => ("Unknown".to_string(), String::new()),
    }
}

pub fn render_tpl<T: Template>(tpl: &T) -> Result<Html<String>, AppError> {
    tpl.render()
        .map(Html)
        .map_err(|e| AppError::Internal(e.to_string()))
}

pub fn extract_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let cookie_header = headers.get(axum::http::header::COOKIE)?.to_str().ok()?;
    cookie_header.split(';').find_map(|c| {
        let c = c.trim();
        c.strip_prefix(&format!("{name}=")).map(|v| v.to_string())
    })
}

pub fn empty_string_as_none<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<String>, D::Error> {
    Ok(Option::<String>::deserialize(d)?.filter(|s| !s.trim().is_empty()))
}

pub fn random_hex_token() -> String {
    uuid::Uuid::new_v4().to_string().replace('-', "")
}

pub fn sha256_hex(value: &str) -> String {
    use sha2::Digest;
    format!("{:x}", sha2::Sha256::digest(value.as_bytes()))
}

pub fn parse_scopes(scope: Option<&str>) -> Vec<String> {
    scope
        .as_deref()
        .unwrap_or("")
        .split_whitespace()
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect()
}

pub async fn generate_token_and_cache<T: Serialize>(
    pool: &Pool,
    prefix: &str,
    payload: &T,
    ttl: i64,
) -> Result<String, AppError> {
    let token = random_hex_token();
    let key = format!("{prefix}{token}");
    crate::infra::cache::set_json(pool, &key, payload, ttl).await?;
    Ok(token)
}

pub async fn validate_cached_token<T: DeserializeOwned>(
    pool: &Pool,
    prefix: &str,
    token: &str,
) -> Option<T> {
    if token.is_empty() {
        return None;
    }
    let key = format!("{prefix}{token}");
    crate::infra::cache::get_json(pool, &key)
        .await
        .ok()
        .flatten()
}


pub fn append_query_params(base: &str, params: &[(&str, &str)]) -> Result<String, AppError> {
    let mut url = url::Url::parse(base)
        .map_err(|_| AppError::BadRequest("invalid redirect uri".into()))?;
    {
        let mut pairs = url.query_pairs_mut();
        for (k, v) in params {
            pairs.append_pair(k, v);
        }
    }
    Ok(url.to_string())
}


pub fn safe_local_path(value: &str) -> Option<String> {
    let decoded = urlencoding::decode(value).ok()?.to_string();

    if decoded.starts_with('/')
        && !decoded.starts_with("//")
        && !decoded.contains('\\')
    {
        Some(decoded)
    } else {
        None
    }
}