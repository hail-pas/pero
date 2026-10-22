use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::crypto::constant_time_eq;

#[derive(Debug, Clone)]
pub struct PkcePair {
    pub code_verifier: String,
    pub code_challenge: String,
}

impl PkcePair {
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        rand::rng().fill_bytes(&mut bytes);
        let code_verifier = URL_SAFE_NO_PAD.encode(bytes);
        let code_challenge = pkce_s256_challenge(&code_verifier);
        Self {
            code_verifier,
            code_challenge,
        }
    }
}

pub fn verify_pkce(code_verifier: &str, code_challenge: &str, method: &str) -> bool {
    if !valid_code_verifier(code_verifier) {
        return false;
    }

    match method {
        "S256" => {
            let hash = Sha256::digest(code_verifier.as_bytes());
            let encoded = URL_SAFE_NO_PAD.encode(hash);
            constant_time_eq(encoded.as_bytes(), code_challenge.as_bytes())
        }
        "plain" => constant_time_eq(code_verifier.as_bytes(), code_challenge.as_bytes()),
        _ => false,
    }
}

pub fn pkce_s256_challenge(code_verifier: &str) -> String {
    let hash = Sha256::digest(code_verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(hash)
}

fn valid_code_verifier(code_verifier: &str) -> bool {
    let len = code_verifier.len();
    (43..=128).contains(&len)
        && code_verifier
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
}
