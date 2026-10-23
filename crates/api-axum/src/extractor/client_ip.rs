use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use ipnetwork::IpNetwork;

use crate::middleware::ResolvedClientIp;

#[derive(Debug, Clone, Copy)]
pub struct ClientIp(pub Option<IpNetwork>);

impl<S: Send + Sync> FromRequestParts<S> for ClientIp {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // Forwarded headers are interpreted only by the trusted-proxy middleware.
        Ok(ClientIp(
            parts
                .extensions
                .get::<ResolvedClientIp>()
                .and_then(|ip| ip.0),
        ))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn forwarded_headers_require_the_trusted_proxy_layer() {
        let (mut parts, _) = axum::http::Request::builder()
            .header("x-forwarded-for", "192.0.2.1")
            .header("x-real-ip", "192.0.2.2")
            .body(())
            .unwrap()
            .into_parts();
        assert_eq!(
            ClientIp::from_request_parts(&mut parts, &())
                .await
                .unwrap()
                .0,
            None
        );
        let resolved = Some("203.0.113.10/32".parse().unwrap());
        parts.extensions.insert(ResolvedClientIp(resolved));
        assert_eq!(
            ClientIp::from_request_parts(&mut parts, &())
                .await
                .unwrap()
                .0,
            resolved
        );
    }
}
