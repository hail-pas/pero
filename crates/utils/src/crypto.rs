pub mod password;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use pero_error::AppError;
use sha2::{Digest, Sha256};

pub fn sha256_hex(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

pub fn generate_token() -> String {
    let bytes: [u8; 32] = rand::random();
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn generate_code() -> String {
    let n: u32 = rand::random_range(0..1_000_000);
    format!("{n:06}")
}

pub fn generate_nonce() -> String {
    let bytes: [u8; 16] = rand::random();
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn hash_secret(secret: &str) -> Result<String, AppError> {
    password::hash_password(secret)
        .map(|result| result.hash)
        .map_err(|_| AppError::internal("secret_hash_failed", "Failed to hash secret"))
}

pub fn verify_secret(secret: &str, hash: &str) -> Result<bool, AppError> {
    password::verify_password(secret, hash)
        .map_err(|_| AppError::internal("secret_verify_failed", "Failed to verify secret"))
}

pub fn hmac_sha256(message: &[u8], key: &[u8]) -> String {
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC key length");
    mac.update(message);
    hex::encode(mac.finalize().into_bytes())
}

pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}

pub fn encode_signed_json<T: serde::Serialize>(
    value: &T,
    key: &[u8],
) -> Result<String, serde_json::Error> {
    let payload = serde_json::to_vec(value).map(|bytes| URL_SAFE_NO_PAD.encode(bytes))?;
    let sig = hmac_sha256(payload.as_bytes(), key);
    Ok(format!("{payload}.{sig}"))
}

pub fn decode_signed_json<T: serde::de::DeserializeOwned>(
    value: &str,
    key: &[u8],
) -> Result<T, serde_json::Error> {
    let (payload, sig) = value
        .rsplit_once('.')
        .ok_or_else(|| serde::de::Error::custom("missing signature"))?;
    use hmac::{Hmac, KeyInit, Mac};
    let signature = hex::decode(sig).map_err(|_| serde::de::Error::custom("invalid signature"))?;
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC key length");
    mac.update(payload.as_bytes());
    mac.verify_slice(&signature)
        .map_err(|_| serde::de::Error::custom("invalid signature"))?;
    let bytes = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| serde::de::Error::custom("invalid base64"))?;
    serde_json::from_slice(&bytes)
}

// Bound both memory usage (Argon2 uses 64 MiB per job) and queued CPU work.
static CRYPTO_JOBS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(4);

pub async fn run_crypto<T: Send + 'static>(
    job: impl FnOnce() -> Result<T, AppError> + Send + 'static,
) -> Result<T, AppError> {
    let permit = CRYPTO_JOBS.try_acquire().map_err(|_| {
        AppError::dependency_failure("crypto_busy", "Credential processing is busy")
    })?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        job()
    })
    .await
    .map_err(|_| AppError::internal("crypto_task_failed", "Credential processing failed"))?
}

pub async fn hash_secret_async(secret: &str) -> Result<String, AppError> {
    let secret = secret.to_owned();
    run_crypto(move || hash_secret(&secret)).await
}

pub async fn verify_secret_async(secret: &str, hash: &str) -> Result<bool, AppError> {
    let (secret, hash) = (secret.to_owned(), hash.to_owned());
    run_crypto(move || verify_secret(&secret, &hash)).await
}

#[cfg(test)]
mod secret_tests {
    #[test]
    fn client_secret_verification_checks_the_entire_input() {
        let prefix = "a".repeat(72);
        let secret = format!("{prefix}original");
        let hash = super::hash_secret(&secret).unwrap();
        assert!(hash.starts_with("$argon2id$"));
        assert!(super::verify_secret(&secret, &hash).unwrap());
        assert!(!super::verify_secret(&format!("{prefix}different"), &hash).unwrap());
    }
}
