use async_trait::async_trait;
use serde_json::Value;

pub struct AuthorizeParams {
    pub endpoint: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub state: String,
    pub code_challenge: Option<String>,
}

pub struct TokenResult {
    pub access_token: String,
    pub raw: Value,
}

pub struct ExchangeCodeParams<'a> {
    pub http_client: &'a dyn pero_http_client_core::HttpClient,
    pub token_endpoint: &'a str,
    pub client_id: &'a str,
    pub client_secret: &'a str,
    pub code: &'a str,
    pub redirect_uri: &'a str,
    pub code_verifier: Option<&'a str>,
}

pub struct AdapterUserInfo {
    pub sub: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub name: Option<String>,
    pub avatar_url: Option<String>,
    pub profile_extra: Value,
}

#[async_trait]
pub trait SocialProviderAdapter: Send + Sync {
    fn build_authorize_url(&self, params: &AuthorizeParams) -> String;

    async fn exchange_code(&self, params: ExchangeCodeParams<'_>) -> Result<TokenResult, String>;

    async fn fetch_userinfo(
        &self,
        http_client: &dyn pero_http_client_core::HttpClient,
        userinfo_endpoint: &str,
        token_result: &TokenResult,
    ) -> Result<AdapterUserInfo, String>;
}
