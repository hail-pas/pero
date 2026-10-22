use base64::Engine;
use chrono::Utc;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::Digest;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    pub scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdTokenClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub exp: i64,
    pub iat: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_time: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub at_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub c_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone_number: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone_number_verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub picture: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sid: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordResetClaims {
    pub sub: String,
    pub exp: i64,
    pub iat: i64,
    pub purpose: String,
    pub jti: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct IdTokenUser {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "phone_number")]
    pub phone: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "phone_number_verified")]
    pub phone_verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub picture: Option<String>,
}

pub struct AccessTokenParams<'a> {
    pub issuer: &'a str,
    pub user_id: &'a str,
    pub client_identifier: &'a str,
    pub scopes: &'a str,
    pub ttl_seconds: i64,
    pub session_id: Option<&'a str>,
    pub kid: Option<&'a str>,
}

pub fn sign_access_token_with_key(
    params: &AccessTokenParams<'_>,
    key: &EncodingKey,
) -> Result<String, jsonwebtoken::errors::Error> {
    let now = Utc::now().timestamp();
    let claims = AccessTokenClaims {
        iss: params.issuer.to_owned(),
        sub: params.user_id.to_owned(),
        aud: params.client_identifier.to_owned(),
        exp: now + params.ttl_seconds,
        iat: now,
        scope: params.scopes.to_owned(),
        sid: params.session_id.map(|s| s.to_owned()),
    };

    let mut header = Header::new(Algorithm::RS256);
    header.typ = Some("at+jwt".to_owned());
    if let Some(k) = params.kid {
        header.kid = Some(k.to_owned());
    }

    encode(&header, &claims, key)
}

pub struct IdTokenParams<'a> {
    pub issuer: &'a str,
    pub user_id: &'a str,
    pub client_identifier: &'a str,
    pub nonce: Option<&'a str>,
    pub auth_time: Option<i64>,
    pub at_hash: Option<&'a str>,
    pub c_hash: Option<&'a str>,
    pub user: &'a IdTokenUser,
    pub ttl_seconds: i64,
    pub session_id: Option<&'a str>,
    pub kid: Option<&'a str>,
}

pub fn oidc_hash(token: &str) -> String {
    use base64::engine::Engine;
    let digest = sha2::Sha256::digest(token.as_bytes());
    let half = &digest[..digest.len() / 2];
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(half)
}

pub fn sign_id_token_with_key(
    params: &IdTokenParams<'_>,
    key: &EncodingKey,
) -> Result<String, jsonwebtoken::errors::Error> {
    let now = Utc::now().timestamp();
    let claims = IdTokenClaims {
        iss: params.issuer.to_owned(),
        sub: params.user_id.to_owned(),
        aud: params.client_identifier.to_owned(),
        exp: now + params.ttl_seconds,
        iat: now,
        nonce: params.nonce.map(|s| s.to_owned()),
        auth_time: params.auth_time,
        at_hash: params.at_hash.map(|s| s.to_owned()),
        c_hash: params.c_hash.map(|s| s.to_owned()),
        name: params.user.name.clone(),
        email: params.user.email.clone(),
        email_verified: params.user.email_verified,
        phone_number: params.user.phone.clone(),
        phone_number_verified: params.user.phone_verified,
        preferred_username: params.user.preferred_username.clone(),
        picture: params.user.picture.clone(),
        sid: params.session_id.map(|s| s.to_owned()),
    };

    let mut header = Header::new(Algorithm::RS256);
    if let Some(k) = params.kid {
        header.kid = Some(k.to_owned());
    }

    encode(&header, &claims, key)
}

pub fn sign_password_reset_token(
    user_id: &str,
    ttl_seconds: i64,
    signing_key: &str,
) -> Result<String, jsonwebtoken::errors::Error> {
    let now = Utc::now().timestamp();
    let claims = PasswordResetClaims {
        sub: user_id.to_owned(),
        exp: now + ttl_seconds,
        iat: now,
        purpose: "password_reset".to_owned(),
        jti: crate::crypto::generate_token(),
    };

    let encoding_key = EncodingKey::from_secret(signing_key.as_bytes());
    encode(&Header::new(Algorithm::HS256), &claims, &encoding_key)
}

pub fn verify_password_reset_token(
    token: &str,
    signing_key: &str,
) -> Result<PasswordResetClaims, jsonwebtoken::errors::Error> {
    let decoding_key = DecodingKey::from_secret(signing_key.as_bytes());
    let mut validation = Validation::new(Algorithm::HS256);
    validation.iss = None;

    let token_data = decode::<PasswordResetClaims>(token, &decoding_key, &validation)?;
    Ok(token_data.claims)
}

pub fn verify_access_token(
    token: &str,
    issuer: &str,
    audience: &str,
    public_key_pem: &str,
) -> Result<AccessTokenClaims, jsonwebtoken::errors::Error> {
    let decoding_key = DecodingKey::from_rsa_pem(public_key_pem.as_bytes())?;
    let validation = rsa_validation(issuer, audience);

    decode_rsa_claims(token, &decoding_key, &validation, TokenPurpose::Access)
}

pub fn verify_access_token_with_rsa_components(
    token: &str,
    issuer: &str,
    audience: &str,
    n: &str,
    e: &str,
) -> Result<AccessTokenClaims, jsonwebtoken::errors::Error> {
    let key = DecodingKey::from_rsa_components(n, e)?;
    decode_rsa_claims(
        token,
        &key,
        &rsa_validation(issuer, audience),
        TokenPurpose::Access,
    )
}

pub fn verify_id_token(
    token: &str,
    issuer: &str,
    audience: &str,
    public_key_pem: &str,
) -> Result<IdTokenClaims, jsonwebtoken::errors::Error> {
    let decoding_key = DecodingKey::from_rsa_pem(public_key_pem.as_bytes())?;
    let validation = rsa_validation(issuer, audience);

    decode_rsa_claims(token, &decoding_key, &validation, TokenPurpose::Identity)
}

/// Verify a logout hint's signature and identity profile, even after expiry.
/// This is NOT an authentication check: callers must associate its sub/sid with
/// the browser session or obtain explicit, CSRF-protected user confirmation.
pub fn verify_logout_hint(
    token: &str,
    issuer: &str,
    audience: &str,
    public_key_pem: &str,
) -> Result<IdTokenClaims, jsonwebtoken::errors::Error> {
    let key = DecodingKey::from_rsa_pem(public_key_pem.as_bytes())?;
    let mut validation = rsa_validation(issuer, audience);
    validation.validate_exp = false;
    decode_rsa_claims(token, &key, &validation, TokenPurpose::Identity)
}

pub fn verify_id_token_with_rsa_components(
    token: &str,
    issuer: &str,
    audience: &str,
    n: &str,
    e: &str,
) -> Result<IdTokenClaims, jsonwebtoken::errors::Error> {
    let decoding_key = DecodingKey::from_rsa_components(n, e)?;
    let validation = rsa_validation(issuer, audience);

    decode_rsa_claims(token, &decoding_key, &validation, TokenPurpose::Identity)
}

enum TokenPurpose {
    Access,
    Identity,
}

fn decode_rsa_claims<T: DeserializeOwned>(
    token: &str,
    key: &DecodingKey,
    validation: &Validation,
    purpose: TokenPurpose,
) -> Result<T, jsonwebtoken::errors::Error> {
    let data = decode::<serde_json::Value>(token, key, validation)?;
    // Token profiles are mutually exclusive; access tokens require an explicit type.
    let valid = match purpose {
        TokenPurpose::Access => {
            data.header.typ.as_deref() == Some("at+jwt")
                && data
                    .claims
                    .get("scope")
                    .is_some_and(serde_json::Value::is_string)
        }
        TokenPurpose::Identity => {
            data.header.typ.as_deref() == Some("JWT") && data.claims.get("scope").is_none()
        }
    };
    if !valid {
        return Err(jsonwebtoken::errors::ErrorKind::InvalidToken.into());
    }
    Ok(serde_json::from_value(data.claims)?)
}

pub fn decode_access_token_claims_unverified(
    token: &str,
) -> Result<AccessTokenClaims, jsonwebtoken::errors::Error> {
    decode_claims_unverified(token)
}

pub fn decode_id_token_claims_unverified(
    token: &str,
) -> Result<IdTokenClaims, jsonwebtoken::errors::Error> {
    decode_claims_unverified(token)
}

pub fn decode_jwt_kid(token: &str) -> Result<String, jsonwebtoken::errors::Error> {
    let header = jsonwebtoken::decode_header(token)?;
    header
        .kid
        .ok_or(jsonwebtoken::errors::ErrorKind::MissingRequiredClaim("kid".into()).into())
}

fn rsa_validation(issuer: &str, audience: &str) -> Validation {
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[issuer]);
    validation.set_audience(&[audience]);
    validation.set_required_spec_claims(&["exp", "iss", "aud"]);
    validation
}

fn decode_claims_unverified<T>(token: &str) -> Result<T, jsonwebtoken::errors::Error>
where
    T: DeserializeOwned,
{
    jsonwebtoken::decode_header(token)?;
    let payload = token
        .split('.')
        .nth(1)
        .expect("decode_header validates JWT shape before payload extraction");
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload)?;
    Ok(serde_json::from_slice(&payload)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    const PRIVATE: &[u8] = include_bytes!("../../../../tests/fixtures/rsa-private.pem");
    const PUBLIC: &str = include_str!("../../../../tests/fixtures/rsa-public.pem");

    #[test]
    fn token_types_cannot_cross_purposes() {
        let now = Utc::now().timestamp();
        let claims =
            serde_json::json!({"iss":"issuer","sub":"user","aud":"client","exp":now+60,"iat":now});
        let sign = |claims: &serde_json::Value, typ: &str| {
            let mut header = Header::new(Algorithm::RS256);
            header.typ = Some(typ.into());
            encode(
                &header,
                claims,
                &EncodingKey::from_rsa_pem(PRIVATE).unwrap(),
            )
            .unwrap()
        };
        let id = sign(&claims, "JWT");
        assert!(verify_id_token(&id, "issuer", "client", PUBLIC).is_ok());
        assert!(verify_access_token(&id, "issuer", "client", PUBLIC).is_err());
        let mut access = claims.clone();
        access["scope"] = "openid".into();
        let at = sign(&access, "at+jwt");
        assert!(verify_access_token(&at, "issuer", "client", PUBLIC).is_ok());
        assert!(verify_id_token(&at, "issuer", "client", PUBLIC).is_err());
        assert!(verify_access_token(&sign(&access, "JWT"), "issuer", "client", PUBLIC).is_err());
        access["scope"] = serde_json::Value::Null;
        let malformed = sign(&access, "JWT");
        assert!(verify_id_token(&malformed, "issuer", "client", PUBLIC).is_err());
        assert!(verify_access_token(&malformed, "issuer", "client", PUBLIC).is_err());
    }
}
