use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use spki::der::Decode;

pub fn rsa_public_key_to_jwk(pem: &str, kid: &str, alg: &str) -> Result<serde_json::Value, String> {
    let (label, document) =
        spki::der::Document::from_pem(pem).map_err(|_| "invalid public key PEM")?;
    if label != "PUBLIC KEY" {
        return Err("expected RSA SubjectPublicKeyInfo".into());
    }
    let info = spki::SubjectPublicKeyInfoRef::from_der(document.as_bytes())
        .map_err(|_| "invalid public key")?;
    if info.algorithm.oid != spki::ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1") {
        return Err("expected RSA key".into());
    }
    let bytes = info
        .subject_public_key
        .as_bytes()
        .ok_or("invalid RSA bit string")?;
    let key = pkcs1::RsaPublicKey::from_der(bytes).map_err(|_| "invalid RSA components")?;
    let n = key.modulus.as_bytes();
    let bits = n.len() * 8 - n.first().map_or(0, |v| v.leading_zeros() as usize);
    if !(2048..=8192).contains(&bits) {
        return Err("RSA key must be 2048–8192 bits".into());
    }
    Ok(
        serde_json::json!({"kty": "RSA", "use": "sig", "kid": kid, "alg": alg,
        "n": URL_SAFE_NO_PAD.encode(n), "e": URL_SAFE_NO_PAD.encode(key.public_exponent.as_bytes())}),
    )
}

/// Parse both PEMs and prove they form a usable signing pair without exposing key material.
pub fn validate_signing_key(public: &str, private: Option<&str>) -> Result<(), String> {
    rsa_public_key_to_jwk(public, "validation", "RS256")?;
    if let Some(private) = private {
        let encoding = jsonwebtoken::EncodingKey::from_rsa_pem(private.as_bytes())
            .map_err(|_| "invalid RSA private key")?;
        let decoding = jsonwebtoken::DecodingKey::from_rsa_pem(public.as_bytes())
            .map_err(|_| "invalid RSA public key")?;
        let claims = serde_json::json!({"exp": chrono::Utc::now().timestamp() + 60, "probe": crate::crypto::generate_nonce()});
        let token = jsonwebtoken::encode(
            &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256),
            &claims,
            &encoding,
        )
        .map_err(|_| "invalid RSA signing key")?;
        jsonwebtoken::decode::<serde_json::Value>(
            &token,
            &decoding,
            &jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256),
        )
        .map_err(|_| "RSA public/private keys do not match")?;
    }
    Ok(())
}
