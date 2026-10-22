use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use pero_error::AppError;
use pero_utils::oauth::jwt::{AccessTokenClaims, IdTokenClaims};
use serde::Deserialize;
use tokio::sync::{Mutex, RwLock};

#[derive(Clone, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    #[serde(default)]
    pub id_token: Option<String>,
}

pub async fn exchange_code(
    http: &reqwest::Client,
    issuer: &str,
    client_id: &str,
    client_secret: &str,
    code: &str,
    redirect_uri: &str,
    code_verifier: &str,
) -> Result<TokenResponse, AppError> {
    let url = pero_utils::oauth::url::issuer_endpoint(issuer, "api/oauth2/token");
    let params = [
        ("grant_type", "authorization_code".to_owned()),
        ("code", code.to_owned()),
        ("redirect_uri", redirect_uri.to_owned()),
        ("client_id", client_id.to_owned()),
        ("client_secret", client_secret.to_owned()),
        ("code_verifier", code_verifier.to_owned()),
    ];

    let resp = http.post(&url).form(&params).send().await.map_err(|e| {
        AppError::dependency_failure("token_request_failed", format!("token request failed: {e}"))
    })?;

    if !resp.status().is_success() {
        let status = resp.status();
        return Err(AppError::dependency_failure(
            "token_exchange_failed",
            format!("token exchange failed ({status})"),
        ));
    }

    bounded_json::<TokenResponse>(resp).await.map_err(|e| {
        AppError::dependency_failure("token_parse_failed", format!("token parse failed: {e}"))
    })
}

pub async fn verify_id_token(
    jwks: &JwksCache,
    http: &reqwest::Client,
    issuer: &str,
    audience: &str,
    id_token: &str,
) -> Result<IdTokenClaims, AppError> {
    let key = token_key(jwks, http, issuer, id_token).await?;

    pero_utils::oauth::jwt::verify_id_token_with_rsa_components(
        id_token, issuer, audience, &key.n, &key.e,
    )
    .map_err(|e| {
        AppError::unauthorized(
            "id_token_invalid",
            format!("ID token verification failed: {e}"),
        )
    })
}

pub async fn verify_access_token(
    jwks: &JwksCache,
    http: &reqwest::Client,
    issuer: &str,
    audience: &str,
    token: &str,
) -> Result<AccessTokenClaims, AppError> {
    let key = token_key(jwks, http, issuer, token).await?;
    pero_utils::oauth::jwt::verify_access_token_with_rsa_components(
        token, issuer, audience, &key.n, &key.e,
    )
    .map_err(|_| AppError::unauthorized("access_token_invalid", "Invalid access token"))
}

async fn token_key(
    jwks: &JwksCache,
    http: &reqwest::Client,
    issuer: &str,
    token: &str,
) -> Result<CachedKey, AppError> {
    let kid = pero_utils::oauth::jwt::decode_jwt_kid(token)
        .map_err(|_| AppError::unauthorized("id_token_invalid", "Invalid signing key ID"))?;
    jwks.get_or_fetch(http, issuer, &kid)
        .await?
        .ok_or_else(|| AppError::unauthorized("id_token_invalid", "Unknown signing key"))
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProvidersApiResponse {
    pub data: ProvidersData,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProvidersData {
    pub providers: Vec<ProviderInfo>,
}

#[derive(Debug, Clone, Deserialize, serde::Serialize)]
pub struct ProviderInfo {
    pub code: String,
    pub name: String,
    #[serde(default)]
    pub icon: String,
}

pub async fn fetch_providers(
    http: &reqwest::Client,
    issuer: &str,
) -> Result<Vec<ProviderInfo>, AppError> {
    let url = pero_utils::oauth::url::issuer_endpoint(issuer, "api/providers");
    let resp = http.get(&url).send().await.map_err(|e| {
        AppError::dependency_failure(
            "providers_request_failed",
            format!("providers request failed: {e}"),
        )
    })?;

    if !resp.status().is_success() {
        tracing::warn!(
            status = %resp.status(),
            "providers API returned non-success status"
        );
        return Ok(vec![]);
    }

    let api_resp: ProvidersApiResponse = bounded_json(resp).await.map_err(|e| {
        AppError::dependency_failure(
            "providers_parse_failed",
            format!("providers parse failed: {e}"),
        )
    })?;

    Ok(api_resp.data.providers)
}

#[derive(Debug, Clone, Deserialize)]
struct JwksResponse {
    keys: Vec<JwkEntry>,
}

#[derive(Debug, Clone, Deserialize)]
struct JwkEntry {
    kid: Option<String>,
    n: String,
    e: String,
}

#[derive(Debug, Clone)]
struct CachedKey {
    n: String,
    e: String,
}

#[derive(Debug, Default)]
struct JwksCacheInner {
    keys: HashMap<String, CachedKey>,
    fetched_at: Option<Instant>,
    attempted_at: Option<Instant>,
    refresh_failed: bool,
}

#[derive(Debug, Clone)]
pub struct JwksCache {
    inner: Arc<RwLock<JwksCacheInner>>,
    ttl: Duration,
    refresh: Arc<Mutex<()>>,
}

impl JwksCache {
    pub fn new(ttl: Duration) -> Self {
        Self {
            inner: Arc::new(RwLock::new(JwksCacheInner::default())),
            ttl,
            refresh: Arc::new(Mutex::new(())),
        }
    }

    async fn get_or_fetch(
        &self,
        http: &reqwest::Client,
        issuer: &str,
        kid: &str,
    ) -> Result<Option<CachedKey>, AppError> {
        // Known, fresh keys do not wait for a refresh of an unrelated kid.
        {
            let cache = self.inner.read().await;
            if cache.fetched_at.is_some_and(|at| at.elapsed() < self.ttl)
                && let Some(key) = cache.keys.get(kid)
            {
                return Ok(Some(key.clone()));
            }
        }
        // Serialize refreshes and throttle misses (including failed fetches) to resist kid floods.
        let _refresh = self.refresh.lock().await;
        {
            let mut cache = self.inner.write().await;
            if cache.fetched_at.is_some_and(|at| at.elapsed() < self.ttl)
                && let Some(key) = cache.keys.get(kid)
            {
                return Ok(Some(key.clone()));
            }
            if cache
                .attempted_at
                .is_some_and(|at| at.elapsed() < Duration::from_secs(5))
            {
                if cache.refresh_failed {
                    return Err(AppError::dependency_failure(
                        "jwks_unavailable",
                        "Signing keys temporarily unavailable",
                    ));
                }
                return Ok(None);
            }
            cache.attempted_at = Some(Instant::now());
            cache.refresh_failed = true;
        }

        self.fetch(http, issuer).await?;

        let cache = self.inner.read().await;
        Ok(cache.keys.get(kid).cloned())
    }

    async fn fetch(&self, http: &reqwest::Client, issuer: &str) -> Result<(), AppError> {
        let url = pero_utils::oauth::url::issuer_endpoint(issuer, "api/oauth2/jwks");
        let resp = http.get(&url).send().await.map_err(|e| {
            AppError::dependency_failure("jwks_request_failed", format!("JWKS request failed: {e}"))
        })?;

        if !resp.status().is_success() {
            let status = resp.status();
            return Err(AppError::dependency_failure(
                "jwks_fetch_failed",
                format!("JWKS fetch failed ({status})"),
            ));
        }

        let jwks: JwksResponse = bounded_json(resp).await.map_err(|e| {
            AppError::dependency_failure("jwks_parse_failed", format!("JWKS parse failed: {e}"))
        })?;

        let mut cache = self.inner.write().await;
        cache.keys.clear();
        for entry in jwks.keys {
            if let Some(kid) = entry.kid {
                cache.keys.insert(
                    kid,
                    CachedKey {
                        n: entry.n,
                        e: entry.e,
                    },
                );
            }
        }
        cache.fetched_at = Some(Instant::now());
        cache.refresh_failed = false;

        tracing::debug!(key_count = cache.keys.len(), "JWKS cache refreshed");
        Ok(())
    }
}

pub(crate) async fn bounded_json<T: serde::de::DeserializeOwned>(
    response: reqwest::Response,
) -> Result<T, AppError> {
    pero_http_client_reqwest::read_response(response, 2 * 1024 * 1024)
        .await?
        .json()
}

#[cfg(test)]
mod cache_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    #[tokio::test]
    async fn refresh_failure_is_not_negative_key_evidence() {
        let count = Arc::new(AtomicUsize::new(0));
        let counter = count.clone();
        let mock = axum::Router::new().route(
            "/api/oauth2/jwks",
            axum::routing::get(move || {
                counter.fetch_add(1, Ordering::SeqCst);
                async { axum::http::StatusCode::SERVICE_UNAVAILABLE }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let issuer = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move { axum::serve(listener, mock).await.unwrap() });
        let cache = JwksCache::new(Duration::from_secs(3600));
        {
            let mut inner = cache.inner.write().await;
            inner.keys.insert(
                "old".into(),
                CachedKey {
                    n: "n".into(),
                    e: "e".into(),
                },
            );
            inner.fetched_at = Some(Instant::now() - Duration::from_secs(3601));
        }
        let http = reqwest::Client::new();
        for _ in 0..3 {
            let error = cache.get_or_fetch(&http, &issuer, "old").await.unwrap_err();
            assert_ne!(error.kind(), pero_error::ErrorKind::Unauthorized);
        }
        assert_eq!(count.load(Ordering::SeqCst), 1);
        task.abort();
    }

    #[tokio::test]
    async fn unknown_kid_refreshes_once_and_misses_are_throttled() {
        let count = Arc::new(AtomicUsize::new(0));
        let counter = count.clone();
        let mock = axum::Router::new().route(
            "/api/oauth2/jwks",
            axum::routing::get(move || {
                counter.fetch_add(1, Ordering::SeqCst);
                async { axum::Json(serde_json::json!({"keys":[{"kid":"new","n":"n","e":"e"}]})) }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let issuer = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move { axum::serve(listener, mock).await.unwrap() });
        let cache = JwksCache::new(Duration::from_secs(3600));
        cache.inner.write().await.fetched_at = Some(Instant::now());
        let http = reqwest::Client::new();
        let (first, second) = tokio::join!(
            cache.get_or_fetch(&http, &issuer, "new"),
            cache.get_or_fetch(&http, &issuer, "new")
        );
        assert!(first.unwrap().is_some() && second.unwrap().is_some());
        assert!(
            cache
                .get_or_fetch(&http, &issuer, "unknown")
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(count.load(Ordering::SeqCst), 1);
        task.abort();
    }
}
