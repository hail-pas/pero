use axum::Json;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct OAuth2ErrorBody {
    pub error: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
}

pub fn invalid_request(message: impl Into<String>) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(OAuth2ErrorBody {
            error: "invalid_request",
            error_description: Some(message.into()),
        }),
    )
        .into_response()
}

pub fn invalid_grant(message: impl Into<String>) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(OAuth2ErrorBody {
            error: "invalid_grant",
            error_description: Some(message.into()),
        }),
    )
        .into_response()
}

pub fn invalid_client(message: impl Into<String>) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, "Basic")],
        Json(OAuth2ErrorBody {
            error: "invalid_client",
            error_description: Some(message.into()),
        }),
    )
        .into_response()
}

pub fn access_denied(message: impl Into<String>) -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(OAuth2ErrorBody {
            error: "access_denied",
            error_description: Some(message.into()),
        }),
    )
        .into_response()
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
        }
    }
}
