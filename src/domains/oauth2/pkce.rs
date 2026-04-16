use crate::shared::constants::oauth2::{PKCE_METHOD_PLAIN, PKCE_METHOD_S256};
use base64::Engine;
use sha2::{Digest, Sha256};

pub fn verify_pkce(code_verifier: &str, code_challenge: &str, method: &str) -> bool {
    match method {
        PKCE_METHOD_S256 => {
            let mut hasher = Sha256::new();
            hasher.update(code_verifier.as_bytes());
            let hash = hasher.finalize();
            let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash);
            encoded == code_challenge
        }
        PKCE_METHOD_PLAIN => code_verifier == code_challenge,
        _ => false,
    }
}
