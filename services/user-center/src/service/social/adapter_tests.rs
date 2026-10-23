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

struct Reply(http::StatusCode);

#[async_trait::async_trait]
impl HttpClient for Reply {
    async fn send(&self, _: http::Request<Vec<u8>>) -> HttpClientResult<HttpResponse> {
        Ok(HttpResponse {
            status: self.0,
            headers: Default::default(),
            body: br#"{"access_token":"token","openid":"openid","unionid":"unionid","sub":"user"}"#
                .to_vec(),
        })
    }
}

#[tokio::test]
async fn upstream_errors_cannot_supply_credentials_or_identities() {
    for status in [
        http::StatusCode::FOUND,
        http::StatusCode::UNAUTHORIZED,
        http::StatusCode::INTERNAL_SERVER_ERROR,
    ] {
        let http = Reply(status);
        for adapter in [
            &oauth2_adapter::OAuth2Adapter as &dyn SocialProviderAdapter,
            &wechat_adapter::WechatAdapter as &dyn SocialProviderAdapter,
        ] {
            assert!(
                adapter
                    .exchange_code(ExchangeCodeParams {
                        http_client: &http,
                        token_endpoint: "https://provider.example/token",
                        client_id: "client",
                        client_secret: "secret",
                        code: "code",
                        redirect_uri: "https://client.example/callback",
                        code_verifier: None,
                    })
                    .await
                    .is_err()
            );
            let token = TokenResult {
                access_token: "token".into(),
                raw: serde_json::json!({"openid":"openid"}),
            };
            assert!(
                adapter
                    .fetch_userinfo(&http, "https://provider.example/userinfo", &token)
                    .await
                    .is_err()
            );
        }
    }
}

#[tokio::test]
async fn wechat_optional_unionid_does_not_change_the_identity() {
    let http = Reply(http::StatusCode::OK);
    for unionid in [None, Some("unionid")] {
        let mut raw = serde_json::json!({"openid":"openid"});
        if let Some(unionid) = unionid {
            raw["unionid"] = unionid.into();
        }
        let token = TokenResult {
            access_token: "token".into(),
            raw,
        };
        let info = wechat_adapter::WechatAdapter
            .fetch_userinfo(&http, "https://provider.example/userinfo", &token)
            .await
            .unwrap();
        assert_eq!(info.sub, "openid");
        assert_eq!(
            info.profile_extra
                .get("unionid")
                .and_then(serde_json::Value::as_str),
            unionid
        );
    }
}
