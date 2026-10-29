use async_trait::async_trait;
use pero_http_client_core::HttpClientExt;
use serde_json::Value;

use super::adapter::{
    AdapterUserInfo, AuthorizeParams, ExchangeCodeParams, SocialProviderAdapter, TokenResult,
};
use super::helper::{int_field, str_field};

pub struct OAuth2Adapter;

#[async_trait]
impl SocialProviderAdapter for OAuth2Adapter {
    fn build_authorize_url(&self, params: &AuthorizeParams) -> String {
        let mut url = params.endpoint.to_owned();
        pero_utils::encode::append_query_param(&mut url, "response_type", "code");
        pero_utils::encode::append_query_param(&mut url, "client_id", &params.client_id);
        pero_utils::encode::append_query_param(&mut url, "redirect_uri", &params.redirect_uri);
        if !params.scope.is_empty() {
            pero_utils::encode::append_query_param(&mut url, "scope", &params.scope);
        }
        pero_utils::encode::append_query_param(&mut url, "state", &params.state);
        if let Some(ref cc) = params.code_challenge {
            pero_utils::encode::append_query_param(&mut url, "code_challenge", cc);
            pero_utils::encode::append_query_param(&mut url, "code_challenge_method", "S256");
        }
        url
    }

    async fn exchange_code(&self, params: ExchangeCodeParams<'_>) -> Result<TokenResult, String> {
        let form_body = {
            let mut ser = url::form_urlencoded::Serializer::new(String::new());
            ser.append_pair("grant_type", "authorization_code");
            ser.append_pair("code", params.code);
            ser.append_pair("redirect_uri", params.redirect_uri);
            ser.append_pair("client_id", params.client_id);
            if !params.client_secret.is_empty() {
                ser.append_pair("client_secret", params.client_secret);
            }
            if let Some(cv) = params.code_verifier {
                ser.append_pair("code_verifier", cv);
            }
            ser.finish()
        };

        let json: Value = params
            .http_client
            .post(params.token_endpoint)
            .header(
                http::header::ACCEPT,
                http::HeaderValue::from_static("application/json"),
            )
            .header(
                http::header::CONTENT_TYPE,
                http::HeaderValue::from_static("application/x-www-form-urlencoded"),
            )
            .body(form_body.into_bytes())
            .send()
            .await
            .map_err(|e| e.to_string())?
            .json()
            .map_err(|e| e.to_string())?;

        let access_token = json
            .get("access_token")
            .and_then(|v| v.as_str())
            .map(String::from)
            .ok_or_else(|| "no access_token in response".to_owned())?;

        Ok(TokenResult {
            access_token,
            raw: json,
        })
    }

    async fn fetch_userinfo(
        &self,
        http_client: &dyn pero_http_client_core::HttpClient,
        userinfo_endpoint: &str,
        token_result: &TokenResult,
    ) -> Result<AdapterUserInfo, String> {
        let json: Value = http_client
            .get(userinfo_endpoint)
            .header(
                http::header::USER_AGENT,
                http::HeaderValue::from_static("Pero/1.0"),
            )
            .bearer_auth(&token_result.access_token)
            .send()
            .await
            .map_err(|e| e.to_string())?
            .json()
            .map_err(|e| e.to_string())?;

        let sub = str_field(&json, "sub")
            .or_else(|| int_field(&json, "id"))
            .unwrap_or_default();

        let name = str_field(&json, "name")
            .or_else(|| str_field(&json, "display_name"))
            .or_else(|| str_field(&json, "login"));

        let avatar_url = str_field(&json, "picture").or_else(|| str_field(&json, "avatar_url"));

        Ok(AdapterUserInfo {
            sub,
            email: str_field(&json, "email"),
            email_verified: json
                .get("email_verified")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            name,
            avatar_url,
            profile_extra: Value::Object(Default::default()),
        })
    }
}
