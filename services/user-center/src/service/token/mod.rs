use std::borrow::Cow;

use pero_api_axum::oauth::TokenSuccessBody;
use pero_cache_redis::rate_limit::{RateLimitError, enforce_rate_limit};
use pero_cache_redis::rate_limit_key::rl_token;
use pero_error::protocol::oauth::OAuth2ErrorCode;
use serde::Deserialize;

use crate::state::app::AppState;

mod authorization_code;
mod client_auth;
mod refresh_token_rotation;
mod token_issuer;

#[derive(Deserialize)]
pub struct TokenRequest {
    pub grant_type: String,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub code_verifier: Option<String>,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
    pub client_id: String,
    pub client_secret: Option<String>,
}

pub enum TokenEndpointResult {
    Success(TokenSuccessBody),
    Error {
        code: OAuth2ErrorCode,
        desc: Option<Cow<'static, str>>,
    },
    Unauthorized(Cow<'static, str>),
}

impl TokenEndpointResult {
    pub(super) fn error(code: OAuth2ErrorCode) -> Self {
        Self::Error { code, desc: None }
    }

    pub(super) fn error_desc(code: OAuth2ErrorCode, desc: impl Into<Cow<'static, str>>) -> Self {
        Self::Error {
            code,
            desc: Some(desc.into()),
        }
    }

    pub(super) fn unauthorized(desc: impl Into<Cow<'static, str>>) -> Self {
        Self::Unauthorized(desc.into())
    }
}

pub struct TokenService<'a> {
    state: &'a AppState,
}

impl<'a> TokenService<'a> {
    pub fn new(state: &'a AppState) -> Self {
        Self { state }
    }

    pub async fn token(&self, form: &TokenRequest, source: &str) -> TokenEndpointResult {
        // Unauthenticated traffic must not consume another client's shared quota.
        let client_rate_limit_key = format!("source:{}", pero_utils::crypto::sha256_hex(source));
        if let Ok(key) = rl_token.key(&client_rate_limit_key) {
            match enforce_rate_limit(&self.state.cache, &key, 60).await {
                Ok(()) => {}
                Err(RateLimitError::Denied { .. }) => {
                    return TokenEndpointResult::error(OAuth2ErrorCode::TemporarilyUnavailable);
                }
                Err(RateLimitError::Redis(e)) => {
                    tracing::error!(error = %e, "rate_limit_check redis error");
                    return TokenEndpointResult::error(OAuth2ErrorCode::TemporarilyUnavailable);
                }
            }
        }

        let client = match self.authenticate_client(form).await {
            Ok(c) => c,
            Err(r) => return r,
        };

        match form.grant_type.as_str() {
            "authorization_code" => self.handle_authorization_code(form, &client).await,
            "refresh_token" => self.handle_refresh_token(form, &client).await,
            _ => TokenEndpointResult::error(OAuth2ErrorCode::UnsupportedGrantType),
        }
    }
}

#[cfg(test)]
mod security_tests;
