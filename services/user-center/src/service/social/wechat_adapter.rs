use async_trait::async_trait;
use pero_http_client_core::HttpClientExt;
use serde_json::Value;

use super::adapter::{
    AdapterUserInfo, AuthorizeParams, ExchangeCodeParams, SocialProviderAdapter, TokenResult,
};
use super::helper::str_field;

pub struct WechatAdapter;

fn check_error(json: &Value) -> Result<(), String> {
    let errcode = json.get("errcode").and_then(|v| v.as_i64()).unwrap_or(0);
    if errcode != 0 {
        let errmsg = json
            .get("errmsg")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown wechat error");
        Err(format!("wechat api error {errcode}: {errmsg}"))
    } else {
        Ok(())
    }
}

#[async_trait]
impl SocialProviderAdapter for WechatAdapter {
    fn build_authorize_url(&self, params: &AuthorizeParams) -> String {
        let mut url = params.endpoint.to_owned();
        pero_utils::encode::append_query_param(&mut url, "appid", &params.client_id);
        pero_utils::encode::append_query_param(&mut url, "redirect_uri", &params.redirect_uri);
        pero_utils::encode::append_query_param(&mut url, "response_type", "code");
        let scope = if params.scope.is_empty() {
            "snsapi_login"
        } else {
            &params.scope
        };
        pero_utils::encode::append_query_param(&mut url, "scope", scope);
        pero_utils::encode::append_query_param(&mut url, "state", &params.state);
        url.push_str("#wechat_redirect");
        url
    }

    async fn exchange_code(&self, params: ExchangeCodeParams<'_>) -> Result<TokenResult, String> {
        let mut url = params.token_endpoint.to_owned();
        pero_utils::encode::append_query_param(&mut url, "appid", params.client_id);
        pero_utils::encode::append_query_param(&mut url, "secret", params.client_secret);
        pero_utils::encode::append_query_param(&mut url, "code", params.code);
        pero_utils::encode::append_query_param(&mut url, "grant_type", "authorization_code");

        let json: Value = params
            .http_client
            .get(&url)
            .no_retry()
            .header(
                http::header::ACCEPT,
                http::HeaderValue::from_static("application/json"),
            )
            .send()
            .await
            .map_err(|e| e.to_string())?
            .json()
            .map_err(|e| e.to_string())?;

        check_error(&json)?;

        let access_token = str_field(&json, "access_token")
            .ok_or_else(|| "no access_token in wechat response".to_owned())?;

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
        let openid = str_field(&token_result.raw, "openid")
            .ok_or_else(|| "no openid in wechat token response".to_owned())?;
        let unionid = str_field(&token_result.raw, "unionid");

        let mut url = userinfo_endpoint.to_owned();
        pero_utils::encode::append_query_param(
            &mut url,
            "access_token",
            &token_result.access_token,
        );
        pero_utils::encode::append_query_param(&mut url, "openid", &openid);

        let json: Value = http_client
            .get(&url)
            .header(
                http::header::USER_AGENT,
                http::HeaderValue::from_static("Pero/1.0"),
            )
            .send()
            .await
            .map_err(|e| e.to_string())?
            .json()
            .map_err(|e| e.to_string())?;

        check_error(&json)?;

        let nickname = str_field(&json, "nickname");
        let headimgurl = str_field(&json, "headimgurl");

        let mut extra = serde_json::Map::new();
        extra.insert("openid".to_owned(), Value::String(openid.clone()));
        if let Some(ref uid) = unionid {
            extra.insert("unionid".to_owned(), Value::String(uid.clone()));
        }

        Ok(AdapterUserInfo {
            // OpenID is stable for this provider's immutable AppID. UnionID is optional
            // and may appear on later logins, so it must not change the identity key.
            sub: openid,
            email: None,
            email_verified: false,
            name: nickname,
            avatar_url: headimgurl,
            profile_extra: Value::Object(extra),
        })
    }
}
