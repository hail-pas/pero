use axum::Json;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Serialize;

use crate::shared::error::ResponseErrorExt;

#[derive(Debug, Serialize)]
pub struct OAuth2ErrorBody {
    pub error: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
}

fn oauth_error(status: StatusCode, code: i32, error: &'static str, message: String) -> Response {
    (
        status,
        Json(OAuth2ErrorBody {
            error,
            error_description: Some(message.clone()),
        }),
    )
        .into_response()
        .with_error_info(code, message)
}

pub fn invalid_request(message: impl Into<String>) -> Response {
    oauth_error(
        StatusCode::BAD_REQUEST,
        40001,
        "invalid_request",
        message.into(),
    )
}

pub fn invalid_grant(message: impl Into<String>) -> Response {
    oauth_error(
        StatusCode::BAD_REQUEST,
        40002,
        "invalid_grant",
        message.into(),
    )
}

pub fn invalid_client(message: impl Into<String>) -> Response {
    let msg = message.into();
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, "Basic")],
        Json(OAuth2ErrorBody {
            error: "invalid_client",
            error_description: Some(msg.clone()),
        }),
    )
        .into_response()
        .with_error_info(40101, msg)
}

pub fn access_denied(message: impl Into<String>) -> Response {
    oauth_error(
        StatusCode::FORBIDDEN,
        40301,
        "access_denied",
        message.into(),
    )
}

pub fn map_app_error(e: crate::shared::error::AppError) -> Response {
    match &e {
        crate::shared::error::AppError::BadRequest(msg) => {
            if msg.contains("client_id") || msg.contains("client is disabled") {
                return invalid_client(msg);
            }
            if msg.contains("redirect_uri") {
                return invalid_grant(msg);
            }
            if msg.contains("authorization code") || msg.contains("PKCE") {
                return invalid_grant(msg);
            }
            if msg.contains("refresh token") {
                return invalid_grant(msg);
            }
            invalid_request(msg)
        }
        crate::shared::error::AppError::Validation(msg) => invalid_request(msg),
        crate::shared::error::AppError::Conflict(msg) => invalid_request(msg),
        crate::shared::error::AppError::Unauthorized => invalid_client("authentication failed"),
        crate::shared::error::AppError::Forbidden(msg) => access_denied(msg),
        crate::shared::error::AppError::NotFound(_) => invalid_grant(e.to_string()),
        _ => {
            tracing::error!(error = %e, "oauth2 internal error");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(OAuth2ErrorBody {
                    error: "server_error",
                    error_description: None,
                }),
            )
                .into_response()
                .with_error_info(50001, "server_error")
        }
    }
}
