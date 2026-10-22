use jsonwebtoken::{Algorithm, Validation, decode, decode_header};
use serde_json::Value;

use super::{SocialLoginError, SocialLoginService, TokenResult};
use crate::db::entity::identity_providers;

impl SocialLoginService<'_> {
    pub(super) async fn validate_oidc_token(
        &self,
        provider: &identity_providers::Model,
        token: &TokenResult,
        nonce: Option<&str>,
        reauthenticate_after: Option<i64>,
    ) -> Result<Value, SocialLoginError> {
        let failure = || SocialLoginError::TokenExchangeFailed("invalid upstream ID token".into());
        let jwt = token
            .raw
            .get("id_token")
            .and_then(Value::as_str)
            .ok_or_else(failure)?;
        let issuer = provider
            .issuer
            .as_deref()
            .filter(|v| !v.is_empty())
            .ok_or_else(failure)?;
        let audience = provider
            .client_id
            .as_deref()
            .filter(|v| !v.is_empty())
            .ok_or_else(failure)?;
        let jwks_uri = provider.jwks_uri.as_deref().ok_or_else(failure)?;
        pero_utils::redirect::validate_provider_endpoint_uri(jwks_uri).map_err(|_| failure())?;
        let header = decode_header(jwt).map_err(|_| failure())?;
        if !matches!(
            header.alg,
            Algorithm::RS256
                | Algorithm::RS384
                | Algorithm::RS512
                | Algorithm::ES256
                | Algorithm::ES384
        ) {
            return Err(failure());
        }
        // Include all trust configuration plus its version, never key by kid alone.
        let configuration = pero_utils::crypto::sha256_hex(&format!(
            "{}|{}|{issuer}|{audience}|{jwks_uri}",
            provider.id, provider.updated_at
        ));
        let key = self
            .jwks
            .key(
                self.http_client,
                &configuration,
                jwks_uri,
                &header,
                std::time::Duration::from_secs(self.oauth2_config.upstream_jwks_cache_ttl_seconds),
            )
            .await
            .map_err(SocialLoginError::Dependency)?
            .ok_or_else(failure)?;
        let mut validation = Validation::new(header.alg);
        validation.set_issuer(&[issuer]);
        validation.set_audience(&[audience]);
        validation.set_required_spec_claims(&["exp", "iat", "iss", "aud", "sub"]);
        validation.validate_nbf = true;
        validation.leeway = 30;
        let claims = decode::<Value>(jwt, &key, &validation)
            .map_err(|_| failure())?
            .claims;
        validate_claims(
            &claims,
            audience,
            nonce,
            time::OffsetDateTime::now_utc().unix_timestamp(),
        )
        .map_err(|_| failure())?;
        validate_authentication_time(
            &claims,
            reauthenticate_after,
            time::OffsetDateTime::now_utc().unix_timestamp(),
        )
        .map_err(|_| failure())?;
        Ok(claims)
    }
}

fn validate_claims(
    claims: &Value,
    audience: &str,
    nonce: Option<&str>,
    now: i64,
) -> Result<(), ()> {
    let expected = nonce.filter(|v| !v.is_empty()).ok_or(())?;
    let actual = claims.get("nonce").and_then(Value::as_str).ok_or(())?;
    if !pero_utils::crypto::constant_time_eq(expected.as_bytes(), actual.as_bytes()) {
        return Err(());
    }
    if claims
        .get("sub")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
        || claims
            .get("iat")
            .and_then(Value::as_i64)
            .is_none_or(|iat| iat > now + 30)
    {
        return Err(());
    }
    let multiple = claims
        .get("aud")
        .and_then(Value::as_array)
        .is_some_and(|aud| aud.len() > 1);
    let azp = claims.get("azp");
    if (multiple || azp.is_some()) && azp.and_then(Value::as_str) != Some(audience) {
        return Err(());
    }
    Ok(())
}

fn validate_authentication_time(claims: &Value, after: Option<i64>, now: i64) -> Result<(), ()> {
    let actual = claims.get("auth_time");
    if actual.is_none() && after.is_none() {
        return Ok(());
    }
    let actual = actual.and_then(Value::as_i64).ok_or(())?;
    if actual > now + 30 || after.is_some_and(|after| actual < after) {
        return Err(());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn forced_upstream_authentication_requires_fresh_auth_time() {
        assert!(validate_authentication_time(&serde_json::json!({}), Some(100), 110).is_err());
        assert!(
            validate_authentication_time(&serde_json::json!({"auth_time":99}), Some(100), 110)
                .is_err()
        );
        assert!(
            validate_authentication_time(&serde_json::json!({"auth_time":100}), Some(100), 110)
                .is_ok()
        );
        assert!(
            validate_authentication_time(&serde_json::json!({"auth_time":200}), None, 110).is_err()
        );
    }
    #[test]
    fn nonce_subject_and_authorized_party_are_required() {
        let mut claims =
            serde_json::json!({"nonce":"fresh", "sub":"user", "iat":100, "aud":["client","other"]});
        assert!(validate_claims(&claims, "client", Some("fresh"), 100).is_err());
        claims["azp"] = "client".into();
        assert!(validate_claims(&claims, "client", Some("fresh"), 100).is_ok());
        assert!(validate_claims(&claims, "client", Some("replayed"), 100).is_err());
        assert!(validate_claims(&claims, "client", None, 100).is_err());
        claims["iat"] = 200.into();
        assert!(validate_claims(&claims, "client", Some("fresh"), 100).is_err());
    }
}
