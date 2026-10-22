use super::{adapter::SocialProviderAdapter, *};
use pero_http_client_core::{HttpClient, HttpClientResult, HttpResponse, NoRetry};
use std::sync::Mutex;

#[derive(Default)]
struct Capture(Mutex<Vec<http::Request<Vec<u8>>>>);

#[async_trait::async_trait]
impl HttpClient for Capture {
    async fn send(&self, request: http::Request<Vec<u8>>) -> HttpClientResult<HttpResponse> {
        self.0.lock().unwrap().push(request);
        Ok(HttpResponse {
            status: http::StatusCode::OK,
            headers: Default::default(),
            body: br#"{"access_token":"token","openid":"id","sub":"id"}"#.to_vec(),
        })
    }
}

#[tokio::test]
async fn adapters_encode_urls_and_mark_only_single_use_gets() {
    let http = Capture::default();
    for (adapter, single_use_get) in [
        (
            &oauth2_adapter::OAuth2Adapter as &dyn SocialProviderAdapter,
            false,
        ),
        (
            &wechat_adapter::WechatAdapter as &dyn SocialProviderAdapter,
            true,
        ),
    ] {
        let params = |endpoint| ExchangeCodeParams {
            http_client: &http,
            token_endpoint: endpoint,
            client_id: "client",
            client_secret: "secret",
            code: "code",
            redirect_uri: "https://client.example.test/callback",
            code_verifier: None,
        };
        let token = adapter
            .exchange_code(params("https://例子.测试/令牌"))
            .await
            .unwrap();
        adapter
            .fetch_userinfo(&http, "https://例子.测试/用户", &token)
            .await
            .unwrap();
        assert!(adapter.exchange_code(params("invalid")).await.is_err());
        assert!(
            adapter
                .fetch_userinfo(&http, "invalid", &token)
                .await
                .is_err()
        );
        let mut requests = http.0.lock().unwrap();
        assert_eq!(requests.len(), 2);
        for request in requests.iter() {
            assert_eq!(request.uri().host(), Some("xn--fsqu00a.xn--0zwm56d"));
            assert!(request.uri().path().contains('%'));
        }
        assert_eq!(
            requests[0].extensions().get::<NoRetry>().is_some(),
            single_use_get
        );
        assert!(requests[1].extensions().get::<NoRetry>().is_none());
        requests.clear();
    }
}
