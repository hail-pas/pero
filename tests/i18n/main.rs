use axum::http::HeaderMap;
use pero::shared::i18n;

#[test]
fn resolves_cookie_before_accept_language_and_default() {
    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::COOKIE,
        "theme=light; pero_locale=zh-CN".parse().unwrap(),
    );
    headers.insert(
        axum::http::header::ACCEPT_LANGUAGE,
        "en-US,en;q=0.9".parse().unwrap(),
    );

    assert_eq!(i18n::resolve_locale(&headers, "en"), "zh-CN");
}

#[test]
fn resolves_supported_accept_language_before_default() {
    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::ACCEPT_LANGUAGE,
        "fr-CA,zh;q=0.8,en;q=0.6".parse().unwrap(),
    );

    assert_eq!(i18n::resolve_locale(&headers, "en"), "zh-CN");
}

#[test]
fn falls_back_to_default_locale_when_no_supported_header_exists() {
    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::ACCEPT_LANGUAGE,
        "fr-CA,fr;q=0.9".parse().unwrap(),
    );

    assert_eq!(i18n::resolve_locale(&headers, "en"), "en");
}
