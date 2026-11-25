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
    let path = raw.split_once('?').map_or(raw, |(path, _)| path);
    if path.contains("//") {
        return default.to_owned();
    }

    let base = url::Url::parse("http://pero.local").expect("static base URL is valid");
    let Ok(parsed) = base.join(raw) else {
        return default.to_owned();
    };
    if parsed.scheme() != "http" || parsed.host_str() != Some("pero.local") {
        return default.to_owned();
    }

    // Only the path determines the navigation target; query values may contain URLs.
    if parsed.path().starts_with("//") {
        return default.to_owned();
    }
    let mut out = parsed.path().to_owned();
    if let Some(query) = parsed.query() {
        out.push('?');
        out.push_str(query);
    }
    out
}

fn valid_raw_uri(uri: &str) -> bool {
    uri.bytes().all(|b| b.is_ascii_graphic()) && !uri.contains('\\')
}

pub fn validate_oauth_redirect_uri(
    uri: &str,
    allow_private_scheme: bool,
) -> Result<(), RedirectUriError> {
    if !valid_raw_uri(uri) {
        return Err(RedirectUriError::Invalid);
    }
    let parsed = url::Url::parse(uri).map_err(|_| RedirectUriError::Invalid)?;
    let scheme = parsed.scheme();
    if DEFAULT_ALLOWED_REDIRECT_SCHEMES.contains(&scheme) {
        // The URL parser normalizes forms such as https:example.com and
        // https:///example.com, but redirects use the original string.
        if !uri
            .split_once("://")
            .is_some_and(|(raw_scheme, authority)| {
                raw_scheme.eq_ignore_ascii_case(scheme)
                    && !authority.is_empty()
                    && !authority.starts_with('/')
            })
        {
            return Err(RedirectUriError::Invalid);
        }
        if parsed.host_str().is_none() {
            return Err(RedirectUriError::MissingHost);
        }
        if scheme == "http" && !is_loopback_http_redirect(&parsed) {
            return Err(RedirectUriError::InsecureHttpHost);
        }
    } else {
        // RFC 8252 §7.1: reverse-domain scheme and an absolute path without an authority.
        if !allow_private_scheme
            || !scheme.contains('.')
            || scheme.split('.').any(|label| {
                label.is_empty()
                    || label.starts_with('-')
                    || label.ends_with('-')
                    || !label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            })
        {
            return Err(RedirectUriError::InvalidScheme);
        }
        if parsed.has_authority() || !parsed.path().starts_with('/') {
            return Err(RedirectUriError::Invalid);
        }
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(RedirectUriError::UserInfoNotAllowed);
    }
    if parsed.fragment().is_some() {
        return Err(RedirectUriError::FragmentNotAllowed);
    }
    Ok(())
}

/// Service URLs are absolute HTTPS URLs (HTTP only for local development).
/// A base URL cannot contain a query or fragment because endpoint paths are appended to it.
pub fn is_valid_service_base_url(uri: &str) -> bool {
    !uri.contains('?') && validate_oauth_redirect_uri(uri, false).is_ok()
}

pub fn validate_oauth_redirect_uris(
    uris: &[String],
    allow_private_scheme: bool,
) -> Result<(), RedirectUriError> {
    for uri in uris {
        validate_oauth_redirect_uri(uri, allow_private_scheme)?;
    }
    Ok(())
}

pub fn validate_provider_endpoint_uri(uri: &str) -> Result<(), ProviderEndpointUriError> {
    if !valid_raw_uri(uri) {
        return Err(ProviderEndpointUriError::Invalid);
    }
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
    let Some(uri) = uri.filter(|value| !value.trim().is_empty()) else {
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
    fn site_redirect_preserves_query_urls_but_rejects_external_targets() {
        use super::safe_site_redirect as redirect;
        let path = "/oauth2/authorize?redirect_uri=https://client.example.test/callback";
        assert_eq!(redirect(path, "/"), path);
        for target in [
            "//example.test",
            "/a//b",
            "/\\example.test",
            "https://example.test",
        ] {
            assert_eq!(redirect(target, "/"), "/");
        }
    }

    #[test]
    fn oauth_private_scheme_requires_opt_in_and_an_authority_free_uri() {
        use super::validate_oauth_redirect_uri as validate;

        let callback = "com.example.app:/oauth2/callback?source=native";
        assert!(validate(callback, true).is_ok());
        assert!(validate(callback, false).is_err());
        for uri in [
            "https://example.test/callback",
            "http://127.0.0.1:8080/callback",
        ] {
            assert!(validate(uri, false).is_ok(), "{uri}");
        }
        for uri in [
            "http://example.test/callback",
            "https://example.test/call\tback",
            "https://example.test/call back",
            "https://example.test\\callback",
            "javascript:alert(1)",
            "myapp:/callback",
            "com..app:/callback",
            "com.example.app://host/callback",
            "com.example.app:callback",
            "com.example.app:/callback#fragment",
            "com.example.app:/call\tback",
        ] {
            assert!(validate(uri, true).is_err(), "{uri}");
        }
    }

    #[test]
    fn service_base_urls_require_secure_absolute_urls_without_queries() {
        for uri in [
            "https://auth.example.test",
            "https://auth.example.test/tenant/",
            "http://localhost:8080",
            "http://127.0.0.1:8080",
            "http://[::1]:8080",
        ] {
            assert!(super::is_valid_service_base_url(uri), "{uri}");
        }
        for uri in [
            "http://auth.example.test",
            "https:auth.example.test",
            "https:///auth.example.test",
            "https://auth.example.test?query=value",
            "https://auth.example.test#fragment",
            "https://user@auth.example.test",
            "/relative",
        ] {
            assert!(!super::is_valid_service_base_url(uri), "{uri}");
            if !uri.contains('?') {
                assert!(
                    super::validate_oauth_redirect_uri(uri, false).is_err(),
                    "{uri}"
                );
            }
        }
    }

    #[test]
    fn provider_endpoints_reject_ambiguous_raw_urls() {
        for uri in [
            "https://example.test/call\tback",
            "https://example.test/call back",
            "https://example.test\\callback",
            " https://example.test/callback",
        ] {
            assert!(super::validate_provider_endpoint_uri(uri).is_err());
            assert!(super::validate_optional_provider_endpoint_uri(Some(uri)).is_err());
        }
        assert!(super::validate_provider_endpoint_uri("https://example.test/a%20b").is_ok());
    }

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
