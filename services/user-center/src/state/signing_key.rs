//! Cache parsed material only. Callers still select an active key from the DB.
use jsonwebtoken::EncodingKey;
use std::sync::{Arc, Mutex};

#[derive(Default)]
pub struct SigningKeyCache {
    // A single entry bounds private key retention and handles same-kid replacement.
    current: Mutex<Option<(String, Arc<EncodingKey>)>>,
}
impl SigningKeyCache {
    pub fn get(&self, pem: &str) -> Result<Arc<EncodingKey>, jsonwebtoken::errors::Error> {
        let fingerprint = pero_utils::crypto::sha256_hex(pem);
        let mut current = self
            .current
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Some((hash, key)) = current.as_ref()
            && hash == &fingerprint
        {
            return Ok(key.clone());
        }
        let key = Arc::new(EncodingKey::from_rsa_pem(pem.as_bytes())?);
        *current = Some((fingerprint, key.clone()));
        Ok(key)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parsing_is_reused_without_accepting_changed_invalid_material() {
        let cache = SigningKeyCache::default();
        let pem = include_str!("../../../../tests/fixtures/rsa-private.pem");
        let first = cache.get(pem).unwrap();
        assert!(Arc::ptr_eq(&first, &cache.get(pem).unwrap()));
        assert!(cache.get("invalid replacement").is_err());
    }
}
