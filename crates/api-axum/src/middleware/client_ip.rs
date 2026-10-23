use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    task::{Context, Poll},
};

use axum::{
    extract::ConnectInfo,
    http::{HeaderMap, Request, Response},
};
use ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};
use pero_config::blocks::ClientIpHeader;
use tower::{Layer, Service};

#[derive(Debug, Clone, Copy)]
pub struct ResolvedClientIp(pub Option<IpNetwork>);

pub fn client_ip_layer(trusted_proxies: Vec<IpNetwork>, header: ClientIpHeader) -> ClientIpLayer {
    ClientIpLayer {
        trusted_proxies: trusted_proxies.into(),
        header,
    }
}

#[derive(Debug, Clone)]
pub struct ClientIpLayer {
    trusted_proxies: Arc<[IpNetwork]>,
    header: ClientIpHeader,
}

impl<S> Layer<S> for ClientIpLayer {
    type Service = ClientIpService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ClientIpService {
            inner,
            trusted_proxies: Arc::clone(&self.trusted_proxies),
            header: self.header,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ClientIpService<S> {
    inner: S,
    trusted_proxies: Arc<[IpNetwork]>,
    header: ClientIpHeader,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for ClientIpService<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>>,
{
    type Response = Response<ResBody>;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut request: Request<ReqBody>) -> Self::Future {
        let resolved = resolve_client_ip(&request, &self.trusted_proxies, self.header);
        request.extensions_mut().insert(ResolvedClientIp(resolved));

        self.inner.call(request)
    }
}

fn resolve_client_ip<B>(
    request: &Request<B>,
    trusted_proxies: &[IpNetwork],
    header: ClientIpHeader,
) -> Option<IpNetwork> {
    let socket_ip = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|connect_info| connect_info.0.ip());

    let resolved_ip = match socket_ip {
        Some(ip) if is_trusted_proxy(ip, trusted_proxies) => {
            extract_from_forwarded_headers(request.headers(), trusted_proxies, header).or(Some(ip))
        }
        Some(ip) => Some(ip),
        None => None,
    };

    resolved_ip.map(ip_to_host_network)
}

fn extract_from_forwarded_headers(
    headers: &HeaderMap,
    trusted_proxies: &[IpNetwork],
    header: ClientIpHeader,
) -> Option<IpAddr> {
    match header {
        ClientIpHeader::Forwarded => {
            resolve_forwarded_chain(forwarded_header_ips(headers), trusted_proxies)
        }
        ClientIpHeader::XForwardedFor => {
            resolve_forwarded_chain(x_forwarded_for_ips(headers), trusted_proxies)
        }
        ClientIpHeader::XRealIp => x_real_ip(headers),
    }
}

fn resolve_forwarded_chain(ips: Vec<IpAddr>, trusted_proxies: &[IpNetwork]) -> Option<IpAddr> {
    if ips.is_empty() {
        return None;
    }

    // 从右向左找第一个“不可信代理”的地址。
    // 这样可以避免直接信任 X-Forwarded-For 最左侧被客户端伪造的 IP。
    ips.iter()
        .rev()
        .copied()
        .find(|ip| !is_trusted_proxy(*ip, trusted_proxies))
        .or_else(|| ips.first().copied())
}

fn forwarded_header_ips(headers: &HeaderMap) -> Vec<IpAddr> {
    let mut ips = Vec::new();

    for value in headers.get_all("forwarded") {
        let Ok(value) = value.to_str() else {
            continue;
        };

        for forwarded_element in value.split(',') {
            for pair in forwarded_element.split(';') {
                let Some((name, value)) = pair.split_once('=') else {
                    continue;
                };

                if name.trim().eq_ignore_ascii_case("for") {
                    if let Some(ip) = parse_header_ip(value) {
                        ips.push(ip);
                    }
                    break;
                }
            }
        }
    }

    ips
}

fn x_forwarded_for_ips(headers: &HeaderMap) -> Vec<IpAddr> {
    let mut ips = Vec::new();

    for value in headers.get_all("x-forwarded-for") {
        let Ok(value) = value.to_str() else {
            continue;
        };

        for part in value.split(',') {
            if let Some(ip) = parse_header_ip(part) {
                ips.push(ip);
            }
        }
    }

    ips
}

fn x_real_ip(headers: &HeaderMap) -> Option<IpAddr> {
    headers
        .get("x-real-ip")
        .and_then(|value| value.to_str().ok())
        .and_then(parse_header_ip)
}

fn parse_header_ip(raw: &str) -> Option<IpAddr> {
    let value = raw.trim().trim_matches('"').trim();

    if value.is_empty() || value.eq_ignore_ascii_case("unknown") {
        return None;
    }

    // 支持 Forwarded: for="[2001:db8::1]:1234"
    if let Some(stripped) = value.strip_prefix('[') {
        let end = stripped.find(']')?;
        return stripped[..end].parse::<IpAddr>().ok();
    }

    // 普通 IPv4 / IPv6
    if let Ok(ip) = value.parse::<IpAddr>() {
        return Some(ip);
    }

    // 支持 192.0.2.1:1234
    if let Ok(socket_addr) = value.parse::<SocketAddr>() {
        return Some(socket_addr.ip());
    }

    None
}

fn is_trusted_proxy(ip: IpAddr, trusted_proxies: &[IpNetwork]) -> bool {
    trusted_proxies.iter().any(|network| network.contains(ip))
}

fn ip_to_host_network(ip: IpAddr) -> IpNetwork {
    match ip {
        IpAddr::V4(ip) => Ipv4Network::new(ip, 32)
            .expect("IPv4 host prefix length 32 must be valid")
            .into(),
        IpAddr::V6(ip) => Ipv6Network::new(ip, 128)
            .expect("IPv6 host prefix length 128 must be valid")
            .into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_the_configured_header_from_a_trusted_peer_is_used() {
        let trusted = ["127.0.0.1/32".parse().unwrap()];
        let request = Request::builder()
            .header("forwarded", "for=198.51.100.99")
            .header("x-forwarded-for", "192.0.2.1, 203.0.113.10")
            .extension(ConnectInfo("127.0.0.1:80".parse::<SocketAddr>().unwrap()))
            .body(())
            .unwrap();
        assert_eq!(
            resolve_client_ip(&request, &trusted, ClientIpHeader::XForwardedFor)
                .unwrap()
                .ip()
                .to_string(),
            "203.0.113.10"
        );
        assert_eq!(
            resolve_client_ip(&request, &trusted, ClientIpHeader::Forwarded)
                .unwrap()
                .ip()
                .to_string(),
            "198.51.100.99"
        );
        assert_eq!(
            resolve_client_ip(&request, &[], ClientIpHeader::Forwarded)
                .unwrap()
                .ip()
                .to_string(),
            "127.0.0.1"
        );
        // Missing selected header must not fall back to attacker-controlled input.
        assert_eq!(
            resolve_client_ip(&request, &trusted, ClientIpHeader::XRealIp)
                .unwrap()
                .ip()
                .to_string(),
            "127.0.0.1"
        );
    }
}
