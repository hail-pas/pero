use axum::extract::{Request, State};
use axum::http::{HeaderMap, header};
use axum::middleware::Next;
use axum::response::Response;

use crate::shared::constants::cookies::LOCALE;
use crate::shared::state::AppState;

pub const SUPPORTED_LOCALES: &[&str] = &["en", "zh-CN"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Locale(pub String);

#[derive(Debug, Clone)]
pub struct UiText {
    pub locale: String,
}

impl UiText {
    pub fn new(locale: impl Into<String>) -> Self {
        Self {
            locale: locale.into(),
        }
    }

    pub fn t(&self, key: &str) -> String {
        rust_i18n::t!(key, locale = &self.locale).to_string()
    }

    pub fn is_zh(&self) -> bool {
        self.locale == "zh-CN"
    }
}

pub async fn locale_middleware(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Response {
    let locale = resolve_locale(req.headers(), &state.config.sso.default_locale);
    req.extensions_mut().insert(Locale(locale));
    next.run(req).await
}

pub fn ui_from_headers(headers: &HeaderMap, default_locale: &str) -> UiText {
    UiText::new(resolve_locale(headers, default_locale))
}

pub fn resolve_locale(headers: &HeaderMap, default_locale: &str) -> String {
    if let Some(locale) = locale_from_cookie(headers) {
        return locale;
    }
    if let Some(locale) = locale_from_accept_language(headers) {
        return locale;
    }
    normalize_supported(default_locale).unwrap_or_else(|| "en".to_string())
}

fn locale_from_cookie(headers: &HeaderMap) -> Option<String> {
    let cookie = headers.get(header::COOKIE)?.to_str().ok()?;
    cookie.split(';').find_map(|part| {
        let part = part.trim();
        let value = part.strip_prefix(&format!("{LOCALE}="))?;
        normalize_supported(value)
    })
}

fn locale_from_accept_language(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(header::ACCEPT_LANGUAGE)?.to_str().ok()?;
    value
        .split(',')
        .filter_map(|item| {
            let lang = item.split(';').next()?.trim();
            normalize_supported(lang)
        })
        .next()
}

fn normalize_supported(value: &str) -> Option<String> {
    let normalized = value.trim().replace('_', "-");
    if normalized.eq_ignore_ascii_case("zh")
        || normalized.eq_ignore_ascii_case("zh-cn")
        || normalized.to_ascii_lowercase().starts_with("zh-hans")
    {
        return Some("zh-CN".to_string());
    }
    if normalized.eq_ignore_ascii_case("en") || normalized.to_ascii_lowercase().starts_with("en-") {
        return Some("en".to_string());
    }
    SUPPORTED_LOCALES
        .iter()
        .find(|locale| locale.eq_ignore_ascii_case(&normalized))
        .map(|locale| (*locale).to_string())
}
