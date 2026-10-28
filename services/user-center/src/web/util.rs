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

pub fn view_response<T: serde::Serialize>(view: &'static str, tpl: T, jar: CookieJar) -> Response {
    (jar, pero_api_axum::form::view(view, tpl)).into_response()
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
        }
    }
}

/// Business failures are bad requests; unavailable dependencies are retryable.
pub fn management_response(result: Result<(), crate::service::ManagementError>) -> Response {
    match result {
        Ok(()) => json_ok(),
        Err(crate::service::ManagementError::Invalid(code)) => {
            let status = match code {
                "registration_closed" | "email_domain_not_allowed" | "forbidden" => {
                    axum::http::StatusCode::FORBIDDEN
                }
                "rate_limited" => axum::http::StatusCode::TOO_MANY_REQUESTS,
                "policy_conflict" => axum::http::StatusCode::CONFLICT,
                "notification_disabled" => axum::http::StatusCode::SERVICE_UNAVAILABLE,
                _ => axum::http::StatusCode::BAD_REQUEST,
            };
            (status, json_error(code)).into_response()
        }
        Err(crate::service::ManagementError::Validation(message)) => json_error(&message),
        Err(error) => dependency_error(error),
    }
}

pub fn dependency_error(error: impl std::fmt::Display) -> Response {
    tracing::error!(%error, "Web dependency unavailable");
    (
        axum::http::StatusCode::SERVICE_UNAVAILABLE,
        axum::Json(serde_json::json!({"error":"service_unavailable"})),
    )
        .into_response()
}

/// Bound user-controlled device metadata before persisting it.
pub fn user_agent(headers: &axum::http::HeaderMap) -> Option<String> {
    headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.chars().take(512).collect())
}
