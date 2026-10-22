use axum_extra::extract::CookieJar;
use pero_api_axum::cookie::{self, CookieOptions};

use crate::config::AppConfig;

pub fn set_pkce_cookies(
    jar: CookieJar,
    code_verifier: &str,
    state: &str,
    config: &AppConfig,
) -> CookieJar {
    let same_site = cookie::parse_same_site(&config.cookie.same_site);
    let domain_opt = cookie::cookie_domain(&config.cookie.domain);
    let path = &config.cookie.path;
    let secure = config.cookie.secure;

    let pkce_cookie = cookie::build_cookie(&CookieOptions {
        name: "admin_pkce",
        value: code_verifier,
        http_only: true,
        secure,
        same_site,
        max_age: time::Duration::minutes(10),
        domain: domain_opt.as_deref(),
        path,
    });
    let jar = jar.add(pkce_cookie);

    let state_cookie = cookie::build_cookie(&CookieOptions {
        name: "admin_state",
        value: state,
        http_only: true,
        secure,
        same_site,
        max_age: time::Duration::minutes(10),
        domain: domain_opt.as_deref(),
        path,
    });
    jar.add(state_cookie)
}

pub fn set_auth_cookies(
    jar: CookieJar,
    token_resp: &crate::oauth2::TokenResponse,
    config: &AppConfig,
) -> CookieJar {
    let same_site = cookie::parse_same_site(&config.cookie.same_site);
    let domain = cookie::cookie_domain(&config.cookie.domain);
    let secure = config.cookie.secure;
    let path = &config.cookie.path;
    let at_max = time::Duration::hours(2);

    let at_cookie = cookie::build_cookie(&CookieOptions {
        name: "admin_at",
        value: &token_resp.access_token,
        http_only: true,
        secure,
        same_site,
        max_age: at_max,
        domain: domain.as_deref(),
        path,
    });
    let mut jar = jar.add(at_cookie);

    if let Some(id_token) = &token_resp.id_token {
        let it_cookie = cookie::build_cookie(&CookieOptions {
            name: "admin_it",
            value: id_token,
            http_only: true,
            secure,
            same_site,
            max_age: at_max,
            domain: domain.as_deref(),
            path,
        });
        jar = jar.add(it_cookie);
    }

    jar
}

pub fn clear_flow_cookies(jar: CookieJar, config: &AppConfig) -> CookieJar {
    clear_named_cookies(jar, config, &["admin_pkce", "admin_state"])
}

pub fn clear_auth_cookies(jar: CookieJar, config: &AppConfig) -> CookieJar {
    clear_named_cookies(
        jar,
        config,
        &["admin_at", "admin_it", "admin_pkce", "admin_state"],
    )
}

fn clear_named_cookies(mut jar: CookieJar, config: &AppConfig, names: &[&str]) -> CookieJar {
    for name in names {
        jar = jar.add(cookie::clear_cookie_with_domain(
            name,
            &config.cookie.path,
            Some(&config.cookie.domain),
        ));
    }
    jar
}
