use askama::Template;
use axum::response::{IntoResponse, Response};
use axum_extra::extract::cookie::CookieJar;
use pero_api_axum::{json_error, json_ok};

pub fn empty_or_opt(s: &str) -> Option<String> {
    pero_utils::string::normalize_optional_string(Some(s.to_owned()))
}

pub fn parse_comma_list(s: &str) -> Vec<String> {
    s.split(',')
        .map(|l| l.trim().to_owned())
        .filter(|l| !l.is_empty())
        .collect()
}

pub fn parse_lines(s: &str) -> Vec<String> {
    s.lines()
        .map(|l| l.trim().to_owned())
        .filter(|l| !l.is_empty())
        .collect()
}

pub fn validate_redirect_uris(uris: &[String]) -> Result<(), &'static str> {
    pero_utils::redirect::validate_oauth_redirect_uris(uris).map_err(|_| "invalid_redirect_uri")
}

pub fn validate_optional_public_url(value: &str) -> Result<(), &'static str> {
    pero_utils::redirect::validate_optional_public_http_url(Some(value)).map_err(|_| "invalid_url")
}

pub fn render_template<T: Template>(tpl: T, jar: CookieJar) -> Response {
    match tpl.render() {
        Ok(html) => (jar, axum::response::Html(html)).into_response(),
        Err(e) => {
            tracing::error!("Template: {e}");
            axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

const REDIRECT_DEFAULT: &str = "/account/profile";

pub fn safe_redirect(raw: &str) -> String {
    pero_utils::redirect::safe_site_redirect(raw, REDIRECT_DEFAULT)
}

use crate::state::app::AppState;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct CsrfOnly {
    #[serde(default)]
    pub csrf_token: String,
}

pub fn verify_csrf_or_json_error(
    jar: &CookieJar,
    csrf_token: &str,
    state: &AppState,
) -> Option<Response> {
    if state.web_security().verify_csrf(jar, csrf_token) {
        None
    } else {
        Some(pero_api_axum::json_error("invalid_csrf"))
    }
}

#[derive(Debug, Clone)]
pub struct UserInfo {
    pub username: String,
    pub name: String,
    pub avatar_url: String,
    pub initial: String,
}

impl UserInfo {
    pub fn from_user(user: &crate::db::entity::users::Model) -> Self {
        Self {
            username: user.username.clone(),
            name: user
                .nickname
                .as_deref()
                .unwrap_or(&user.username)
                .to_owned(),
            avatar_url: user.avatar_url.clone().unwrap_or_default(),
            initial: user
                .nickname
                .as_deref()
                .or(user.email.as_deref())
                .unwrap_or(&user.username)
                .chars()
                .next()
                .unwrap_or('?')
                .to_uppercase()
                .to_string(),
        }
    }
}

/// Keep the existing JSON contract while distinguishing dependency failure.
pub fn management_response(result: Result<(), crate::service::ManagementError>) -> Response {
    match result {
        Ok(()) => json_ok(),
        Err(crate::service::ManagementError::Invalid(code)) => json_error(code),
        Err(error) => {
            tracing::error!(%error, "Management mutation failed");
            let mut response = json_error("update_failed");
            *response.status_mut() = axum::http::StatusCode::SERVICE_UNAVAILABLE;
            response
        }
    }
}
