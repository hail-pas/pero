use std::time::Duration;

use http::HeaderMap;
use pero_error::{AppError, ErrorKind};
use pero_http_client_core::{
    HttpClient, HttpClientConfig, HttpClientResult, HttpResponse, RetryConfig,
};
use pero_validate_core::{Validatable, ValidationError, ValidationLocation, ValidationSource};
use reqwest::Client;

#[derive(Debug, Clone)]
pub struct ReqwestHttpClient {
    client: Client,
    retry: RetryConfig,
    public_only: bool,
    max_response_bytes: usize,
}

impl ReqwestHttpClient {
    pub fn from_config(config: &HttpClientConfig) -> Result<Self, ValidationError> {
        Self::build(config, false)
    }

    /// Public IdP/notification traffic uses validated DNS results as the actual connection addresses.
    pub fn from_public_config(config: &HttpClientConfig) -> Result<Self, ValidationError> {
        Self::build(config, true)
    }

    fn build(config: &HttpClientConfig, public_only: bool) -> Result<Self, ValidationError> {
        config.validate()?;

        // reqwest 0.13 defaults to platform roots; retain the previous Mozilla
        // trust store on every host, including minimal musl deployments.
        let roots = webpki_root_certs::TLS_SERVER_ROOT_CERTS
            .iter()
            .map(|der| reqwest::Certificate::from_der(der.as_ref()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| {
                ValidationError::malformed_input(
                    ValidationSource::new(ValidationLocation::Config),
                    format!("Invalid bundled TLS root: {error}"),
                )
            })?;
        let mut builder = Client::builder()
            .tls_certs_only(roots)
            .retry(reqwest::retry::never())
            .timeout(Duration::from_secs(config.timeout_secs))
            .connect_timeout(Duration::from_secs(config.connect_timeout_secs))
            .pool_idle_timeout(Duration::from_secs(config.pool_idle_timeout_secs))
            .pool_max_idle_per_host(config.pool_max_idle_per_host)
            .redirect(reqwest::redirect::Policy::none());

        if public_only {
            builder = builder
                .no_proxy()
                .dns_resolver(std::sync::Arc::new(PublicResolver));
        }

        if let Some(user_agent) = &config.user_agent {
            builder = builder.user_agent(user_agent.as_str());
        }

        let client = builder.build().map_err(|err| {
            ValidationError::malformed_input(
                ValidationSource::new(ValidationLocation::Config),
                format!("Failed to build reqwest client {err}"),
            )
        })?;

        Ok(Self {
            client,
            retry: config.retry.clone(),
            public_only,
            max_response_bytes: config.max_response_bytes,
        })
    }

    pub fn inner(&self) -> &Client {
        &self.client
    }
}

#[async_trait::async_trait]
impl HttpClient for ReqwestHttpClient {
    async fn send(&self, request: http::Request<Vec<u8>>) -> HttpClientResult<HttpResponse> {
        if self.public_only
            && pero_utils::redirect::validate_provider_endpoint_uri(&request.uri().to_string())
                .is_err()
        {
            return Err(AppError::dependency_failure(
                "http_private_endpoint",
                "Invalid public HTTPS endpoint",
            ));
        }
        if !self.retry.enabled
            || !request.method().is_idempotent()
            || request
                .extensions()
                .get::<pero_http_client_core::NoRetry>()
                .is_some()
        {
            let req = convert_request(&self.client, request)?;
            let response = self.client.execute(req).await.map_err(map_reqwest_error)?;
            return read_response(response, self.max_response_bytes).await;
        }

        let mut attempt = 0;
        loop {
            if attempt > 0 {
                tokio::time::sleep(self.retry.delay_for_attempt(attempt)).await;
            }
            let req = convert_request(&self.client, request.clone())?;
            match self.client.execute(req).await {
                Ok(response) => return read_response(response, self.max_response_bytes).await,
                Err(err) if attempt < self.retry.max_retries && is_retryable(&err) => {
                    attempt += 1;
                }
                Err(err) => return Err(map_reqwest_error(err)),
            }
        }
    }
}

fn convert_request(
    client: &Client,
    request: http::Request<Vec<u8>>,
) -> HttpClientResult<reqwest::Request> {
    let (parts, body) = request.into_parts();

    let url = reqwest::Url::parse(&parts.uri.to_string()).map_err(|err| {
        AppError::internal(
            "http_client_url_parse_failed",
            "Failed to parse request URL",
        )
        .with_source(err)
    })?;

    let mut builder = client.request(parts.method, url);

    for (name, value) in parts.headers.iter() {
        builder = builder.header(name, value);
    }

    builder.body(body).build().map_err(|err| {
        AppError::internal(
            "http_client_build_failed",
            "Failed to build reqwest request",
        )
        .with_source(err)
    })
}

pub async fn read_response(
    mut response: reqwest::Response,
    limit: usize,
) -> HttpClientResult<HttpResponse> {
    let status = response.status();
    let headers: HeaderMap = response.headers().clone();
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(map_reqwest_error)? {
        if chunk.len() > limit.saturating_sub(body.len()) {
            return Err(AppError::dependency_failure(
                "http_response_too_large",
                "Upstream response exceeded the configured limit",
            ));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(HttpResponse {
        status,
        headers,
        body,
    })
}

#[derive(Debug)]
struct PublicResolver;
impl reqwest::dns::Resolve for PublicResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let hostname = name.as_str().to_owned();
        Box::pin(async move {
            let addresses: Vec<_> = tokio::net::lookup_host((hostname.as_str(), 0))
                .await?
                .collect();
            if addresses.is_empty()
                || addresses
                    .iter()
                    .any(|address| !pero_utils::redirect::is_public_ip(address.ip()))
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "Non-public DNS result",
                )
                .into());
            }
            Ok(Box::new(addresses.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

fn map_reqwest_error(err: reqwest::Error) -> AppError {
    let err = err.without_url();
    if err.is_timeout() {
        AppError::new(
            ErrorKind::Timeout,
            "http_client_timeout",
            "HTTP request to upstream timed out",
        )
        .with_source(err)
    } else if err.is_connect() {
        AppError::dependency_failure(
            "http_client_connect_failed",
            "Failed to connect to upstream service",
        )
        .with_source(err)
    } else {
        AppError::dependency_failure(
            "http_client_request_failed",
            "HTTP request to upstream failed",
        )
        .with_source(err)
    }
}

fn is_retryable(err: &reqwest::Error) -> bool {
    err.is_connect() || err.is_timeout() || (err.is_request() && !err.is_redirect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    #[tokio::test]
    async fn retries_do_not_replay_single_use_exchanges() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let count = Arc::new(AtomicUsize::new(0));
        let observed = count.clone();
        let server = tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                observed.fetch_add(1, Ordering::SeqCst);
                drop(stream);
            }
        });
        let config = HttpClientConfig {
            retry: RetryConfig {
                enabled: true,
                max_retries: 2,
                base_delay_millis: 1,
                max_delay_millis: 2,
            },
            ..Default::default()
        };
        let client = ReqwestHttpClient::from_config(&config).unwrap();
        let request = http::Request::post(format!("http://{address}/token"))
            .body(vec![])
            .unwrap();
        assert!(client.send(request).await.is_err());
        assert_eq!(count.load(Ordering::SeqCst), 1);
        use pero_http_client_core::HttpClientExt;
        assert!(
            client
                .get(&format!("http://{address}/token?code=one-time"))
                .no_retry()
                .send()
                .await
                .is_err()
        );
        assert_eq!(count.load(Ordering::SeqCst), 2);
        server.abort();
    }

    #[tokio::test]
    async fn redirects_are_returned_without_following_them() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = [0; 1024];
            assert!(stream.read(&mut buffer).await.unwrap() > 0);
            stream.write_all(b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/private\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.unwrap();
        });
        let client = ReqwestHttpClient::from_config(&HttpClientConfig::default()).unwrap();
        let response = client
            .send(
                http::Request::get(format!("http://{address}/"))
                    .body(vec![])
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status, http::StatusCode::FOUND);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn idempotent_retries_and_request_deadlines_remain_bounded() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let count = Arc::new(AtomicUsize::new(0));
        let observed = count.clone();
        let server = tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                observed.fetch_add(1, Ordering::SeqCst);
                drop(stream);
            }
        });
        let config = HttpClientConfig {
            retry: RetryConfig {
                enabled: true,
                max_retries: 2,
                base_delay_millis: 1,
                max_delay_millis: 2,
            },
            ..Default::default()
        };
        let client = ReqwestHttpClient::from_config(&config).unwrap();
        assert!(
            client
                .send(
                    http::Request::get(format!("http://{address}/"))
                        .body(vec![])
                        .unwrap()
                )
                .await
                .is_err()
        );
        assert_eq!(count.load(Ordering::SeqCst), 3);
        server.abort();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.unwrap();
            std::future::pending::<()>().await;
        });
        let client = ReqwestHttpClient::from_config(&HttpClientConfig {
            timeout_secs: 1,
            ..Default::default()
        })
        .unwrap();
        let start = std::time::Instant::now();
        assert!(
            client
                .send(
                    http::Request::post(format!("http://{address}/"))
                        .body(vec![])
                        .unwrap()
                )
                .await
                .is_err()
        );
        assert!(start.elapsed() < Duration::from_secs(3));
        server.abort();

        // The request-local deadline also covers a stalled response body.
        use pero_http_client_core::HttpClientExt;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/slow", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = [0; 2048];
            let read = stream.read(&mut buffer).await.unwrap();
            assert!(
                std::str::from_utf8(&buffer[..read])
                    .unwrap()
                    .contains("x-request-timeout: 100")
            );
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n")
                .await
                .unwrap();
            std::future::pending::<()>().await;
        });
        let start = std::time::Instant::now();
        let error = client
            .get(&endpoint)
            .timeout(Duration::from_millis(100))
            .send()
            .await
            .unwrap_err();
        assert_eq!(error.kind(), ErrorKind::Timeout);
        assert!(start.elapsed() < Duration::from_secs(1));
        server.abort();
    }

    #[tokio::test]
    async fn response_size_and_private_endpoint_are_bounded() {
        use tokio::io::AsyncWriteExt;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            use tokio::io::AsyncReadExt;
            let mut buffer = [0; 1024];
            let _ = stream.read(&mut buffer).await;
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\n0123456789",
                )
                .await
                .unwrap();
        });
        let config = HttpClientConfig {
            max_response_bytes: 4,
            ..Default::default()
        };
        let client = ReqwestHttpClient::from_config(&config).unwrap();
        assert!(
            client
                .send(
                    http::Request::get(format!("http://{address}/"))
                        .body(vec![])
                        .unwrap()
                )
                .await
                .is_err()
        );
        server.await.unwrap();
        let public = ReqwestHttpClient::from_public_config(&config).unwrap();
        assert!(
            public
                .send(
                    http::Request::get("https://[::ffff:127.0.0.1]/")
                        .body(vec![])
                        .unwrap()
                )
                .await
                .is_err()
        );
        use reqwest::dns::Resolve;
        assert!(
            PublicResolver
                .resolve("localhost".parse().unwrap())
                .await
                .is_err()
        );
    }
}
