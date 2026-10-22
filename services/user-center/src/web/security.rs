use askama::Template;
use axum::response::Response;
use axum_extra::extract::cookie::{Cookie, CookieJar};
use serde::{Deserialize, Serialize};

use crate::config::SsoConfig;

#[derive(Clone, Copy)]
pub struct SsoCookieFactory<'a> {
    sso: &'a SsoConfig,
}

impl<'a> SsoCookieFactory<'a> {
    pub fn new(sso: &'a SsoConfig) -> Self {
        Self { sso }
    }

    pub fn session_cookie_name(&self) -> &str {
        &self.sso.session_cookie_name
    }

    pub fn nonce_cookie_name(&self) -> String {
        format!("{}_nonce", self.sso.session_cookie_name)
    }

    pub fn auth_req_cookie_name(&self) -> String {
        format!("{}_req", self.sso.session_cookie_name)
    }

    pub fn social_state_cookie_name(&self) -> String {
        format!("{}_social_state", self.sso.session_cookie_name)
    }

    pub fn build_session_cookie(&self, token: &str) -> Cookie<'static> {
        self.build_cookie(
            &self.sso.session_cookie_name,
            token,
            true,
            self.sso.session_ttl_seconds,
        )
    }

    pub fn build_short_lived_cookie(
        &self,
        name: &str,
        value: &str,
        max_age_seconds: u64,
    ) -> Cookie<'static> {
        self.build_cookie(name, value, true, max_age_seconds)
    }

    pub fn clear_cookie(&self, name: &str) -> Cookie<'static> {
        let config = self.app_cookie_config();
        pero_api_axum::cookie::clear_app_cookie(&config, name)
    }

    pub fn encode_auth_request(
        &self,
        value: &AuthReqCookieValue,
    ) -> Result<String, serde_json::Error> {
        value.encode(self.sso.cookie_signing_secret.expose_secret().as_bytes())
    }

    pub fn decode_auth_request(&self, raw: &str) -> Result<AuthReqCookieValue, serde_json::Error> {
        AuthReqCookieValue::decode(
            raw,
            self.sso.cookie_signing_secret.expose_secret().as_bytes(),
        )
    }

    fn build_cookie(
        &self,
        name: &str,
        value: &str,
        http_only: bool,
        max_age_seconds: u64,
    ) -> Cookie<'static> {
        let config = self.app_cookie_config();
        pero_api_axum::cookie::build_app_cookie(
            &config,
            name,
            value,
            http_only,
            time::Duration::seconds(max_age_seconds as i64),
        )
    }

    fn app_cookie_config(&self) -> pero_api_axum::cookie::AppCookieConfig<'_> {
        pero_api_axum::cookie::AppCookieConfig {
            secure: self.sso.cookie_secure,
            same_site: &self.sso.cookie_same_site,
            domain: &self.sso.cookie_domain,
            path: &self.sso.cookie_path,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthReqCookieValue {
    pub auth_request_id: uuid::Uuid,
    pub user_id: uuid::Uuid,
}

impl AuthReqCookieValue {
    pub fn encode(&self, key: &[u8]) -> Result<String, serde_json::Error> {
        pero_api_axum::cookie::encode_signed_json(self, key)
    }

    pub fn decode(value: &str, key: &[u8]) -> Result<Self, serde_json::Error> {
        pero_api_axum::cookie::decode_signed_json(value, key)
    }
}

#[derive(Clone, Copy)]
pub struct SsoWebSecurity<'a> {
    sso: &'a SsoConfig,
    cookies: SsoCookieFactory<'a>,
}

impl<'a> SsoWebSecurity<'a> {
    pub fn new(sso: &'a SsoConfig) -> Self {
        Self {
            sso,
            cookies: SsoCookieFactory::new(sso),
        }
    }

    pub fn cookies(&self) -> SsoCookieFactory<'a> {
        self.cookies
    }

    pub fn csrf_cookie_name(&self) -> &'static str {
        pero_api_axum::csrf::DEFAULT_CSRF_COOKIE_NAME
    }

    pub fn generate_csrf(&self, jar: CookieJar) -> (CookieJar, String) {
        pero_api_axum::csrf::generate_csrf(jar, &self.csrf_config())
    }

    pub fn ensure_csrf(&self, jar: CookieJar) -> (CookieJar, String) {
        pero_api_axum::csrf::ensure_csrf(jar, &self.csrf_config())
    }

    pub fn verify_csrf(&self, jar: &CookieJar, form_token: &str) -> bool {
        pero_api_axum::csrf::verify_csrf(jar, form_token, &self.csrf_config())
    }

    pub fn render_with_csrf<T, F>(&self, jar: CookieJar, build: F) -> Response
    where
        T: Template,
        F: FnOnce(String) -> T,
    {
        pero_api_axum::form::render_askama_with_csrf(jar, &self.csrf_config(), build)
    }

    fn csrf_config(&self) -> pero_api_axum::csrf::CsrfConfig<'_> {
        pero_api_axum::csrf::CsrfConfig::new(
            self.cookies.app_cookie_config(),
            &self.sso.session_cookie_name,
            self.sso.cookie_signing_secret.expose_secret(),
        )
    }
}
