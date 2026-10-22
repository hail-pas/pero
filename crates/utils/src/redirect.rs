const DEFAULT_ALLOWED_REDIRECT_SCHEMES: &[&str] = &["http", "https"];

pub fn safe_site_redirect(raw: &str, default: &str) -> String {
    if raw.is_empty() {
        return default.to_owned();
    }
    if raw.as_bytes().first() != Some(&b'/') || raw.starts_with("//") || raw.contains('\\') {
        return default.to_owned();
    }
    if raw.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return default.to_owned();
    }
    if raw.contains("//") {
        return default.to_owned();
    }

    let base = url::Url::parse("http://pero.local").expect("static base URL is valid");
    let Ok(parsed) = base.join(raw) else {
        return default.to_owned();
    };
    if parsed.scheme() != "http" || parsed.host_str() != Some("pero.local") {
        return default.to_owned();
    }

    let mut out = parsed.path().to_owned();
    if let Some(query) = parsed.query() {
        out.push('?');
        out.push_str(query);
    }
    out
}

pub fn validate_oauth_redirect_uri(uri: &str) -> Result<(), RedirectUriError> {
    let parsed = url::Url::parse(uri).map_err(|_| RedirectUriError::Invalid)?;
    let scheme = parsed.scheme();
    if !DEFAULT_ALLOWED_REDIRECT_SCHEMES.contains(&scheme) {
        return Err(RedirectUriError::InvalidScheme);
    }
    if parsed.host_str().is_none() {
        return Err(RedirectUriError::MissingHost);
    }
    if scheme == "http" && !is_loopback_http_redirect(&parsed) {
        return Err(RedirectUriError::InsecureHttpHost);
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(RedirectUriError::UserInfoNotAllowed);
    }
    if parsed.fragment().is_some() {
        return Err(RedirectUriError::FragmentNotAllowed);
    }
    Ok(())
}

pub fn validate_oauth_redirect_uris(uris: &[String]) -> Result<(), RedirectUriError> {
    for uri in uris {
        validate_oauth_redirect_uri(uri)?;
    }
    Ok(())
}

pub fn validate_provider_endpoint_uri(uri: &str) -> Result<(), ProviderEndpointUriError> {
    let parsed = url::Url::parse(uri).map_err(|_| ProviderEndpointUriError::Invalid)?;
    if parsed.scheme() != "https" {
        return Err(ProviderEndpointUriError::InvalidScheme);
    }
    if parsed.host_str().is_none() {
        return Err(ProviderEndpointUriError::MissingHost);
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(ProviderEndpointUriError::UserInfoNotAllowed);
    }
    if parsed.fragment().is_some() {
        return Err(ProviderEndpointUriError::FragmentNotAllowed);
    }
    if parsed.host().is_some_and(is_private_or_loopback_host) {
        return Err(ProviderEndpointUriError::PrivateHostNotAllowed);
    }
    Ok(())
}

pub fn validate_optional_provider_endpoint_uri(
    uri: Option<&str>,
) -> Result<(), ProviderEndpointUriError> {
    let Some(uri) = uri.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(());
    };
    validate_provider_endpoint_uri(uri)
}

pub fn validate_public_http_url(uri: &str) -> Result<(), PublicHttpUrlError> {
    let parsed = url::Url::parse(uri).map_err(|_| PublicHttpUrlError::Invalid)?;
    if !DEFAULT_ALLOWED_REDIRECT_SCHEMES.contains(&parsed.scheme()) {
        return Err(PublicHttpUrlError::InvalidScheme);
    }
    if parsed.host_str().is_none() {
        return Err(PublicHttpUrlError::MissingHost);
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(PublicHttpUrlError::UserInfoNotAllowed);
    }
    Ok(())
}

pub fn validate_optional_public_http_url(uri: Option<&str>) -> Result<(), PublicHttpUrlError> {
    let Some(uri) = uri.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(());
    };
    validate_public_http_url(uri)
}

fn is_loopback_http_redirect(parsed: &url::Url) -> bool {
    parsed.host().is_some_and(|host| match host {
        url::Host::Domain(domain) => domain.eq_ignore_ascii_case("localhost"),
        url::Host::Ipv4(ip) => ip.is_loopback(),
        url::Host::Ipv6(ip) => ip.is_loopback(),
    })
}

fn is_private_or_loopback_host(host: url::Host<&str>) -> bool {
    match host {
        url::Host::Domain(domain) => domain.eq_ignore_ascii_case("localhost"),
        url::Host::Ipv4(ip) => !is_public_ip(ip.into()),
        url::Host::Ipv6(ip) => !is_public_ip(ip.into()),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedirectUriError {
    Invalid,
    InvalidScheme,
    InsecureHttpHost,
    MissingHost,
    UserInfoNotAllowed,
    FragmentNotAllowed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderEndpointUriError {
    Invalid,
    InvalidScheme,
    MissingHost,
    UserInfoNotAllowed,
    FragmentNotAllowed,
    PrivateHostNotAllowed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublicHttpUrlError {
    Invalid,
    InvalidScheme,
    MissingHost,
    UserInfoNotAllowed,
}

/// Only globally routable addresses are allowed for server-side provider connections.
pub fn is_public_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(ip) => {
            let [a, b, _, _] = ip.octets();
            !ip.is_private()
                && !ip.is_loopback()
                && !ip.is_link_local()
                && !ip.is_broadcast()
                && !ip.is_documentation()
                && !ip.is_unspecified()
                && a != 0
                && a < 224
                && !(a == 100 && (64..=127).contains(&b))
                && !(a == 198 && (b == 18 || b == 19))
                && !(a == 192 && b == 0)
        }
        std::net::IpAddr::V6(ip) => {
            if let Some(v4) = ip.to_ipv4_mapped() {
                return is_public_ip(v4.into());
            }
            let s = ip.segments();
            (s[0] & 0xe000) == 0x2000
                && s[0] != 0x2002
                && !(s[0] == 0x2001 && (s[1] < 0x200 || s[1] == 0xdb8))
                && s[0] != 0x3fff
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn private_addresses_and_ipv4_mapped_ipv6_are_blocked() {
        for ip in [
            "127.0.0.1",
            "10.0.0.1",
            "100.64.0.1",
            "169.254.169.254",
            "224.0.0.1",
            "::1",
            "::ffff:127.0.0.1",
            "fc00::1",
            "2001:db8::1",
        ] {
            assert!(!super::is_public_ip(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["8.8.8.8", "2606:4700:4700::1111"] {
            assert!(super::is_public_ip(ip.parse().unwrap()));
        }
        assert!(super::validate_provider_endpoint_uri("https://[::ffff:127.0.0.1]/").is_err());
    }
}
