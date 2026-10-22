use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use ipnetwork::IpNetwork;

use crate::middleware::ResolvedClientIp;

#[derive(Debug, Clone, Copy)]
pub struct ClientIp(pub Option<IpNetwork>);

impl<S: Send + Sync> FromRequestParts<S> for ClientIp {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        if let Some(resolved) = parts.extensions.get::<ResolvedClientIp>() {
            return Ok(ClientIp(resolved.0));
        }
        let ip = extract_from_headers(&parts.headers);
        Ok(ClientIp(ip))
    }
}

impl ClientIp {
    pub fn for_rate_limit(&self) -> String {
        self.0.map(|ip| ip.to_string()).unwrap_or_default()
    }
}

impl std::fmt::Display for ClientIp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            Some(ip) => write!(f, "{ip}"),
            None => f.write_str("unknown"),
        }
    }
}

fn extract_from_headers(headers: &axum::http::HeaderMap) -> Option<IpNetwork> {
    if let Some(xff) = headers.get("x-forwarded-for") {
        let val = xff.to_str().ok()?;
        let first = val.split(',').next()?.trim();
        if !first.is_empty()
            && let Ok(ip) = first.parse()
        {
            return Some(ip);
        }
    }

    if let Some(real) = headers.get("x-real-ip") {
        let val = real.to_str().ok()?.trim();
        if !val.is_empty()
            && let Ok(ip) = val.parse()
        {
            return Some(ip);
        }
    }

    None
}
