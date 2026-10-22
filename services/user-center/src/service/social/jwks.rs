//! Bounded, per-configuration JWKS cache with single-flight refresh.
use jsonwebtoken::{
    DecodingKey, Header,
    jwk::{Jwk, JwkSet, KeyOperations, PublicKeyUse},
};
use pero_error::AppError;
use pero_http_client_core::{HttpClientExt, HttpClientHandle};
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::{Mutex, RwLock};

struct CachedKey {
    jwk: Jwk,
    key: Option<Arc<DecodingKey>>,
}
#[derive(Default)]
struct Snapshot {
    keys: Vec<CachedKey>,
    fetched: Option<Instant>,
    attempted: Option<Instant>,
    failed: bool,
}
#[derive(Default)]
struct Entry {
    data: RwLock<Snapshot>,
    refresh: Mutex<()>,
}
#[derive(Default)]
pub struct JwksCache {
    entries: Mutex<HashMap<String, Arc<Entry>>>,
}
fn unavailable() -> AppError {
    AppError::dependency_failure("jwks_unavailable", "Upstream signing keys unavailable")
}
fn select(snapshot: &Snapshot, header: &Header) -> Option<Arc<DecodingKey>> {
    let mut candidates = snapshot.keys.iter().filter(|entry| {
        let key = &entry.jwk;
        header
            .kid
            .as_ref()
            .is_none_or(|kid| key.common.key_id.as_ref() == Some(kid))
            && key
                .common
                .public_key_use
                .as_ref()
                .is_none_or(|usage| matches!(usage, PublicKeyUse::Signature))
            && key
                .common
                .key_operations
                .as_ref()
                .is_none_or(|ops| ops.contains(&KeyOperations::Verify))
            && key
                .common
                .key_algorithm
                .is_none_or(|alg| alg.to_string() == format!("{:?}", header.alg))
    });
    let first = candidates.next()?;
    if candidates.next().is_some() {
        return None;
    }
    first.key.clone()
}
impl JwksCache {
    pub async fn key(
        &self,
        http: &HttpClientHandle,
        configuration: &str,
        uri: &str,
        header: &Header,
        ttl: Duration,
    ) -> Result<Option<Arc<DecodingKey>>, AppError> {
        let entry = {
            let mut entries = self.entries.lock().await;
            if !entries.contains_key(configuration) && entries.len() >= 128 {
                // Eviction never invalidates an in-flight Arc or expands the bound.
                if let Some(old) = entries.keys().next().cloned() {
                    entries.remove(&old);
                }
            }
            entries.entry(configuration.to_owned()).or_default().clone()
        };
        {
            let data = entry.data.read().await;
            if data.fetched.is_some_and(|at| at.elapsed() < ttl)
                && let Some(key) = select(&data, header)
            {
                return Ok(Some(key));
            }
        }
        let _refresh = entry.refresh.lock().await;
        {
            let data = entry.data.read().await;
            if data.fetched.is_some_and(|at| at.elapsed() < ttl)
                && let Some(key) = select(&data, header)
            {
                return Ok(Some(key));
            }
            if data
                .attempted
                .is_some_and(|at| at.elapsed() < Duration::from_secs(5))
            {
                if data.failed {
                    return Err(unavailable());
                }
                if !ttl.is_zero() && data.fetched.is_some_and(|at| at.elapsed() < ttl) {
                    return Ok(None);
                }
            }
        }
        {
            let mut data = entry.data.write().await;
            data.attempted = Some(Instant::now());
            data.failed = true;
        }
        let response = http.get(uri).send().await?;
        if !response.status.is_success() {
            return Err(unavailable());
        }
        let keys: JwkSet = response.json()?;
        let keys = keys
            .keys
            .into_iter()
            .map(|jwk| {
                let key = DecodingKey::from_jwk(&jwk).ok().map(Arc::new);
                CachedKey { jwk, key }
            })
            .collect();
        let mut data = entry.data.write().await;
        data.keys = keys;
        data.fetched = Some(Instant::now());
        data.failed = false;
        Ok(select(&data, header))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pero_http_client_core::{HttpClient, HttpClientResult, HttpResponse};
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct Mock {
        calls: Arc<AtomicUsize>,
        fail: Arc<AtomicUsize>,
    }
    #[async_trait::async_trait]
    impl HttpClient for Mock {
        async fn send(&self, _: http::Request<Vec<u8>>) -> HttpClientResult<HttpResponse> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            tokio::task::yield_now().await;
            let jwk = pero_utils::oauth::jwk::rsa_public_key_to_jwk(
                include_str!("../../../../../tests/fixtures/rsa-public.pem"),
                if self.fail.load(Ordering::SeqCst) == 2 {
                    "rotated"
                } else {
                    "key"
                },
                "RS256",
            )
            .unwrap();
            Ok(HttpResponse {
                status: if self.fail.load(Ordering::SeqCst) == 1 {
                    http::StatusCode::SERVICE_UNAVAILABLE
                } else {
                    http::StatusCode::OK
                },
                headers: Default::default(),
                body: serde_json::to_vec(&serde_json::json!({"keys":[jwk]})).unwrap(),
            })
        }
    }
    #[tokio::test]
    async fn cache_is_bounded_versioned_and_distinguishes_failed_refresh_from_unknown_kid() {
        let calls = Arc::new(AtomicUsize::new(0));
        let fail = Arc::new(AtomicUsize::new(0));
        let http: HttpClientHandle = Arc::new(Mock {
            calls: calls.clone(),
            fail: fail.clone(),
        });
        let cache = JwksCache::default();
        let mut header = Header::new(jsonwebtoken::Algorithm::RS256);
        header.kid = Some("key".into());
        let ttl = Duration::from_secs(60);
        let (a, b) = tokio::join!(
            cache.key(&http, "v1", "https://provider.test/jwks", &header, ttl),
            cache.key(&http, "v1", "https://provider.test/jwks", &header, ttl)
        );
        let a = a.unwrap().unwrap();
        let b = b.unwrap().unwrap();
        assert!(Arc::ptr_eq(&a, &b));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        header.kid = Some("unknown".into());
        assert!(
            cache
                .key(&http, "v1", "https://provider.test/jwks", &header, ttl)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        fail.store(1, Ordering::SeqCst);
        for _ in 0..3 {
            assert!(
                cache
                    .key(&http, "v2", "https://provider.test/jwks", &header, ttl)
                    .await
                    .is_err()
            );
        }
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        fail.store(0, Ordering::SeqCst);
        header.kid = Some("key".into());
        // Default zero TTL still consults upstream on every call.
        for _ in 0..2 {
            assert!(
                cache
                    .key(
                        &http,
                        "v3",
                        "https://provider.test/jwks",
                        &header,
                        Duration::ZERO
                    )
                    .await
                    .unwrap()
                    .is_some()
            );
        }
        assert_eq!(calls.load(Ordering::SeqCst), 4);
        // Expired entries fail closed on refresh errors and do not serve stale keys.
        let entry = cache.entries.lock().await["v1"].clone();
        {
            let mut data = entry.data.write().await;
            data.fetched = Some(Instant::now() - ttl);
            data.attempted = None;
        }
        fail.store(1, Ordering::SeqCst);
        assert!(
            cache
                .key(&http, "v1", "https://provider.test/jwks", &header, ttl)
                .await
                .is_err()
        );
        fail.store(0, Ordering::SeqCst);
        // A successful rotation replaces the set; removed keys are no longer accepted.
        entry.data.write().await.attempted = None;
        fail.store(2, Ordering::SeqCst);
        header.kid = Some("rotated".into());
        assert!(
            cache
                .key(&http, "v1", "https://provider.test/jwks", &header, ttl)
                .await
                .unwrap()
                .is_some()
        );
        header.kid = Some("key".into());
        assert!(
            cache
                .key(&http, "v1", "https://provider.test/jwks", &header, ttl)
                .await
                .unwrap()
                .is_none()
        );
        fail.store(0, Ordering::SeqCst);
        for i in 0..130 {
            cache
                .key(
                    &http,
                    &format!("config-{i}"),
                    "https://provider.test/jwks",
                    &header,
                    ttl,
                )
                .await
                .unwrap();
        }
        assert_eq!(cache.entries.lock().await.len(), 128);
    }
}
