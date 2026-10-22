use axum::extract::FromRequestParts;
use axum::http::request::Parts;

use crate::headers;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Locale(pub String);

impl<S: Send + Sync> FromRequestParts<S> for Locale {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let locale = parts
            .headers
            .get(headers::ACCEPT_LANGUAGE)
            .and_then(|v| v.to_str().ok())
            .map(parse_accept_language)
            .unwrap_or_else(|| "en".to_owned());
        Ok(Locale(locale))
    }
}

fn parse_accept_language(header: &str) -> String {
    header
        .split(',')
        .next()
        .unwrap_or("en")
        .split(';')
        .next()
        .unwrap_or("en")
        .trim()
        .to_owned()
}
