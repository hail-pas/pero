use base64::Engine;
use http::{HeaderName, HeaderValue, Method};
use pero_error::{AppError, ErrorKind};
use serde::de::DeserializeOwned;
use std::time::Duration;

use crate::client::{HttpClient, HttpClientResult, HttpResponse};

pub struct HttpClientRequest<'a> {
    client: &'a dyn HttpClient,
    method: Method,
    url: &'a str,
    headers: http::HeaderMap,
    body: HttpClientResult<Vec<u8>>,
    timeout: Option<Duration>,
    no_retry: bool,
}

impl<'a> HttpClientRequest<'a> {
    pub(crate) fn new(client: &'a dyn HttpClient, method: Method, url: &'a str) -> Self {
        Self {
            client,
            method,
            url,
            headers: http::HeaderMap::new(),
            body: Ok(Vec::new()),
            timeout: None,
            no_retry: false,
        }
    }

    pub fn header(mut self, key: impl Into<HeaderName>, value: impl Into<HeaderValue>) -> Self {
        self.headers.insert(key.into(), value.into());
        self
    }

    pub fn headers(mut self, headers: http::HeaderMap) -> Self {
        for (key, value) in headers {
            if let Some(key) = key {
                self.headers.insert(key, value);
            }
        }
        self
    }

    pub fn bearer_auth(mut self, token: &str) -> Self {
        self.headers.insert(
            http::header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}"))
                .unwrap_or_else(|_| HeaderValue::from_static("Bearer")),
        );
        self
    }

    pub fn basic_auth(mut self, username: &str, password: &str) -> Self {
        let encoded =
            base64::engine::general_purpose::STANDARD.encode(format!("{username}:{password}"));
        self.headers.insert(
            http::header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Basic {encoded}"))
                .unwrap_or_else(|_| HeaderValue::from_static("Basic")),
        );
        self
    }

    /// Limit the complete transport operation, including retries and response reads.
    pub fn timeout(mut self, duration: Duration) -> Self {
        self.timeout = Some(duration);
        self
    }

    pub fn no_retry(mut self) -> Self {
        self.no_retry = true;
        self
    }

    pub fn json<T: serde::Serialize + Sync>(mut self, body: &T) -> Self {
        self.headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        self.body = serde_json::to_vec(body).map_err(|_| {
            AppError::internal(
                "http_client_json_encode_failed",
                "Failed to encode JSON request",
            )
        });
        self
    }

    pub fn form<T: serde::Serialize + Sync>(mut self, body: &T) -> Self {
        self.headers.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        );
        self.body = serde_urlencoded::to_string(body)
            .map(String::into_bytes)
            .map_err(|_| {
                AppError::internal(
                    "http_client_form_encode_failed",
                    "Failed to encode form request",
                )
            });
        self
    }

    pub fn body(mut self, body: Vec<u8>) -> Self {
        self.body = Ok(body);
        self
    }

    pub async fn send(self) -> HttpClientResult<HttpResponse> {
        let client = self.client;
        let timeout = self.timeout;
        let request = self.build_request()?;
        let response = match timeout {
            Some(duration) => tokio::time::timeout(duration, client.send(request))
                .await
                .map_err(|_| {
                    AppError::new(
                        ErrorKind::Timeout,
                        "http_client_timeout",
                        "HTTP request to upstream timed out",
                    )
                })??,
            None => client.send(request).await?,
        };
        response.error_for_status()
    }

    pub async fn into<T: DeserializeOwned + Send + 'a>(self) -> HttpClientResult<T> {
        let response = self.send().await?;
        response.json()
    }

    fn build_request(self) -> HttpClientResult<http::Request<Vec<u8>>> {
        let body = self.body?;

        let url = url::Url::parse(self.url).map_err(|_| {
            AppError::internal(
                "http_client_url_parse_failed",
                "Failed to parse request URL",
            )
        })?;
        let mut builder = http::Request::builder()
            .method(self.method)
            .uri(url.as_str());

        for (key, value) in self.headers {
            if let Some(key) = key {
                builder = builder.header(key, value);
            }
        }

        if let Some(timeout) = self.timeout {
            // Preserve the existing upstream hint; the local deadline is enforced in send().
            builder = builder.header("x-request-timeout", timeout.as_millis().to_string());
        }

        let mut request = builder.body(body).map_err(|err| {
            AppError::internal("http_client_build_failed", "Failed to build HTTP request")
                .with_source(err)
        })?;
        if self.no_retry {
            request.extensions_mut().insert(crate::NoRetry);
        }
        Ok(request)
    }
}

pub trait HttpClientExt: HttpClient + Sized {
    fn request<'a>(&'a self, method: Method, url: &'a str) -> HttpClientRequest<'a> {
        HttpClientRequest::new(self, method, url)
    }

    fn get<'a>(&'a self, url: &'a str) -> HttpClientRequest<'a> {
        self.request(Method::GET, url)
    }

    fn post<'a>(&'a self, url: &'a str) -> HttpClientRequest<'a> {
        self.request(Method::POST, url)
    }

    fn put<'a>(&'a self, url: &'a str) -> HttpClientRequest<'a> {
        self.request(Method::PUT, url)
    }

    fn patch<'a>(&'a self, url: &'a str) -> HttpClientRequest<'a> {
        self.request(Method::PATCH, url)
    }

    fn delete<'a>(&'a self, url: &'a str) -> HttpClientRequest<'a> {
        self.request(Method::DELETE, url)
    }
}

impl<T: HttpClient> HttpClientExt for T {}

#[cfg(test)]
mod tests {
    use super::*;

    struct UnusedClient;
    #[async_trait::async_trait]
    impl HttpClient for UnusedClient {
        async fn send(&self, _: http::Request<Vec<u8>>) -> HttpClientResult<HttpResponse> {
            unreachable!("request construction does not send traffic")
        }
    }

    #[test]
    fn request_urls_are_encoded_and_invalid_urls_fail_without_exposing_credentials() {
        let request = HttpClientRequest::new(
            &UnusedClient,
            Method::GET,
            "https://例子.测试/用户?code=abc",
        )
        .build_request()
        .unwrap();
        assert_eq!(request.uri().host(), Some("xn--fsqu00a.xn--0zwm56d"));
        assert_eq!(request.uri().path(), "/%E7%94%A8%E6%88%B7");
        assert_eq!(request.uri().query(), Some("code=abc"));
        let error = HttpClientRequest::new(&UnusedClient, Method::GET, "invalid?secret=private")
            .build_request()
            .unwrap_err();
        assert!(!error.to_string().contains("private"));
    }

    #[tokio::test]
    async fn serialization_errors_do_not_send_empty_requests() {
        let invalid_json = std::collections::HashMap::from([(vec![1, 2], 3)]);
        assert!(
            UnusedClient
                .post("https://example.test")
                .json(&invalid_json)
                .send()
                .await
                .is_err()
        );
        assert!(
            UnusedClient
                .post("https://example.test")
                .form(&"invalid top-level form")
                .send()
                .await
                .is_err()
        );
        let json = UnusedClient
            .post("https://example.test")
            .json(&serde_json::json!({"a":1}))
            .build_request()
            .unwrap();
        assert_eq!(json.body(), br#"{"a":1}"#);
        let form = UnusedClient
            .post("https://example.test")
            .form(&[("a", "b c")])
            .build_request()
            .unwrap();
        assert_eq!(form.body(), b"a=b+c");
    }
}
