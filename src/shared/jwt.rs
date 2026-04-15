use crate::config::OidcConfig;
use crate::shared::error::AppError;
use base64::Engine;
use chrono::{TimeDelta, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TokenClaims {
    pub sub: String,
    pub roles: Vec<String>,
    pub exp: i64,
    pub iat: i64,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct IdTokenClaims {
    pub sub: String,
    pub iss: String,
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    pub auth_time: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nickname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub picture: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone_number: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone_number_verified: Option<bool>,
}

pub struct JwtKeys {
    pub key_id: String,
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    public_n: String,
    public_e: String,
}

impl JwtKeys {
    pub fn load(oidc_config: &OidcConfig) -> Result<Self, AppError> {
        let private_pem = std::fs::read_to_string(&oidc_config.private_key_path)
            .map_err(|e| AppError::Internal(format!("Failed to read private key: {e}")))?;
        let public_pem = std::fs::read_to_string(&oidc_config.public_key_path)
            .map_err(|e| AppError::Internal(format!("Failed to read public key: {e}")))?;

        let encoding_key = EncodingKey::from_rsa_pem(private_pem.as_bytes())
            .map_err(|e| AppError::Internal(format!("JWT encoding key error: {e}")))?;

        let decoding_key = DecodingKey::from_rsa_pem(public_pem.as_bytes())
            .map_err(|e| AppError::Internal(format!("JWT decoding key error: {e}")))?;

        let public_key =
            <rsa::RsaPublicKey as rsa::pkcs8::DecodePublicKey>::from_public_key_pem(&public_pem)
                .map_err(|e| AppError::Internal(format!("Failed to parse public key: {e}")))?;

        use rsa::traits::PublicKeyParts;
        let public_n =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be());
        let public_e =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be());

        Ok(Self {
            key_id: oidc_config.key_id.clone(),
            encoding_key,
            decoding_key,
            public_n,
            public_e,
        })
    }

    pub fn public_key_jwk(&self) -> serde_json::Value {
        serde_json::json!({
            "kty": "RSA",
            "kid": self.key_id,
            "use": "sig",
            "alg": "RS256",
            "n": self.public_n,
            "e": self.public_e,
        })
    }
}

pub fn sign_access_token(
    user_id: &str,
    roles: Vec<String>,
    keys: &JwtKeys,
    ttl_minutes: i64,
) -> Result<String, AppError> {
    let now = Utc::now();
    let claims = TokenClaims {
        sub: user_id.to_string(),
        roles,
        exp: (now + TimeDelta::minutes(ttl_minutes)).timestamp(),
        iat: now.timestamp(),
    };
    let mut header = Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some(keys.key_id.clone());
    encode(&header, &claims, &keys.encoding_key)
        .map_err(|e| AppError::Internal(format!("JWT sign failed: {e}")))
}

pub fn verify_token(token: &str, keys: &JwtKeys) -> Result<TokenClaims, AppError> {
    let validation = Validation::new(jsonwebtoken::Algorithm::RS256);
    let token_data = decode::<TokenClaims>(token, &keys.decoding_key, &validation)
        .map_err(|_| AppError::Unauthorized)?;
    Ok(token_data.claims)
}

pub fn sign_id_token(claims: &IdTokenClaims, keys: &JwtKeys) -> Result<String, AppError> {
    let mut header = Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some(keys.key_id.clone());
    encode(&header, claims, &keys.encoding_key)
        .map_err(|e| AppError::Internal(format!("ID token sign failed: {e}")))
}
