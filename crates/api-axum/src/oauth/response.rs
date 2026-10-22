use axum::http::header;
use axum::response::{IntoResponse, Response};
use pero_error::protocol::oauth::{BearerError, OAuth2Error, OAuth2ErrorCode};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct TokenSuccessBody {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
    pub scope: String,
}

pub fn token_success_response(body: TokenSuccessBody) -> Response {
    (
        axum::http::StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/json; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
        serde_json::to_string(&body).unwrap_or_default(),
    )
        .into_response()
}

pub fn token_error_response(code: OAuth2ErrorCode, desc: Option<&str>) -> Response {
    let err = match desc {
        Some(d) => OAuth2Error::new(code).with_description(d),
        None => OAuth2Error::new(code),
    };
    let body = serde_json::to_string(&err.response_body())
        .unwrap_or_else(|_| "{\"error\":\"server_error\"}".to_owned());
    (
        err.status,
        [
            (header::CONTENT_TYPE, "application/json; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
        body,
    )
        .into_response()
}

pub fn token_error_unauthorized_response(desc: &str) -> Response {
    let err = OAuth2Error::invalid_client(desc);
    let body = serde_json::to_string(&err.response_body())
        .unwrap_or_else(|_| "{\"error\":\"invalid_client\"}".to_owned());
    (
        err.status,
        [
            (header::CONTENT_TYPE, "application/json; charset=utf-8"),
            (
                header::WWW_AUTHENTICATE,
                "Basic realm=\"OAuth2 token endpoint\"",
            ),
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
        body,
    )
        .into_response()
}

pub fn bearer_error_response(err: BearerError) -> Response {
    let body = serde_json::json!({
        "error": err.code.as_str(),
        "error_description": err.description.as_deref().unwrap_or(err.code.as_str()),
    });
    (
        err.status,
        [
            (header::WWW_AUTHENTICATE, err.www_authenticate_value()),
            (
                header::CONTENT_TYPE,
                "application/json; charset=utf-8".to_owned(),
            ),
            (header::CACHE_CONTROL, "no-store".to_owned()),
            (header::PRAGMA, "no-cache".to_owned()),
        ],
        body.to_string(),
    )
        .into_response()
}
