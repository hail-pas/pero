use base64::Engine;
use sha2::{Digest, Sha256};

pub fn verify_pkce(code_verifier: &str, code_challenge: &str, method: &str) -> bool {
    match method {
        "S256" => {
            let mut hasher = Sha256::new();
            hasher.update(code_verifier.as_bytes());
            let hash = hasher.finalize();
            let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash);
            encoded == code_challenge
        }
        "plain" => code_verifier == code_challenge,
        _ => false,
    }
}
