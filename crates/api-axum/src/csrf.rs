use axum_extra::extract::cookie::{Cookie, CookieJar};
use cookie::time::Duration;

use crate::cookie::{AppCookieConfig, build_app_cookie};

pub const DEFAULT_CSRF_COOKIE_NAME: &str = "pero_csrf";

pub struct CsrfConfig<'a> {
    pub cookie: AppCookieConfig<'a>,
    pub csrf_cookie_name: &'a str,
    pub session_cookie_name: &'a str,
    pub signing_secret: &'a str,
    pub token_ttl: Duration,
}

impl<'a> CsrfConfig<'a> {
    pub fn new(
        cookie: AppCookieConfig<'a>,
        session_cookie_name: &'a str,
        signing_secret: &'a str,
    ) -> Self {
        Self {
            cookie,
            csrf_cookie_name: DEFAULT_CSRF_COOKIE_NAME,
            session_cookie_name,
            signing_secret,
            token_ttl: Duration::hours(1),
        }
    }
}

pub fn generate_csrf(jar: CookieJar, config: &CsrfConfig<'_>) -> (CookieJar, String) {
    let random = pero_utils::crypto::generate_token();
    let ts = format!("{:x}", time::OffsetDateTime::now_utc().unix_timestamp());
    let session_token = jar
        .get(config.session_cookie_name)
        .map(|c| c.value().to_owned());
    let key = csrf_binding_key(session_token.as_deref(), config.signing_secret);
    let message = format!("{random}.{ts}");
    let hmac = pero_utils::crypto::hmac_sha256(message.as_bytes(), &key);
    let token = format!("{random}.{ts}.{hmac}");
    let cookie = build_csrf_cookie(config, &token);
    (jar.add(cookie), token)
}

pub fn ensure_csrf(jar: CookieJar, config: &CsrfConfig<'_>) -> (CookieJar, String) {
    let existing = jar
        .get(config.csrf_cookie_name)
        .map(|c| c.value().to_owned());
    if let Some(token) = existing
        && verify_csrf_token(&token, config, &jar)
    {
        return (jar, token);
    }
    generate_csrf(jar, config)
}

pub fn verify_csrf(jar: &CookieJar, form_token: &str, config: &CsrfConfig<'_>) -> bool {
    if form_token.is_empty() {
        return false;
    }
    let cookie_token = match jar.get(config.csrf_cookie_name) {
        Some(c) => c.value(),
        None => return false,
    };
    if !pero_utils::crypto::constant_time_eq(cookie_token.as_bytes(), form_token.as_bytes()) {
        return false;
    }
    verify_csrf_token(form_token, config, jar)
}

fn verify_csrf_token(token: &str, config: &CsrfConfig<'_>, jar: &CookieJar) -> bool {
    let parts: Vec<&str> = token.splitn(3, '.').collect();
    if parts.len() != 3 {
        return false;
    }
    let (random, ts, hmac_hex) = (parts[0], parts[1], parts[2]);
    let ts_seconds: i64 = match i64::from_str_radix(ts, 16) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    if now.saturating_sub(ts_seconds) > config.token_ttl.whole_seconds() {
        return false;
    }
    let session_token = jar
        .get(config.session_cookie_name)
        .map(|c| c.value().to_owned());
    let key = csrf_binding_key(session_token.as_deref(), config.signing_secret);
    let message = format!("{random}.{ts}");
    let expected = pero_utils::crypto::hmac_sha256(message.as_bytes(), &key);
    pero_utils::crypto::constant_time_eq(expected.as_bytes(), hmac_hex.as_bytes())
}

fn csrf_binding_key(session_token: Option<&str>, csrf_secret: &str) -> Vec<u8> {
    let mut key = Vec::new();
    if let Some(token) = session_token {
        key.extend_from_slice(pero_utils::crypto::sha256_hex(token).as_bytes());
    }
    key.extend_from_slice(csrf_secret.as_bytes());
    key
}

fn build_csrf_cookie(config: &CsrfConfig<'_>, token: &str) -> Cookie<'static> {
    build_app_cookie(
        &config.cookie,
        config.csrf_cookie_name,
        token,
        false,
        config.token_ttl,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn multiple_tabs_keep_a_valid_token_but_login_changes_invalidate_it() {
        let config = CsrfConfig::new(
            AppCookieConfig {
                secure: false,
                same_site: "Lax",
                domain: "",
                path: "/",
            },
            "sso",
            "test-signing-secret",
        );
        let (jar, first) = ensure_csrf(CookieJar::new(), &config);
        let (jar, second) = ensure_csrf(jar, &config);
        assert_eq!(first, second);
        assert!(verify_csrf(&jar, &first, &config));
        let jar = jar.add(Cookie::new("sso", "new-session"));
        assert!(!verify_csrf(&jar, &first, &config));
        let (jar, third) = ensure_csrf(jar, &config);
        assert_ne!(first, third);
        assert!(verify_csrf(&jar, &third, &config));
    }
}
