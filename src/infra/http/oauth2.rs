use axum::Json;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Serialize;

use crate::domain::oauth2::typed_error::OAuth2TypedError;
use crate::infra::http::error::ResponseErrorExt;

#[derive(Debug, Serialize)]
pub struct OAuth2ErrorBody {
    pub error: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
}

#[derive(Debug)]
pub enum OAuth2ErrorCode {
    InvalidRequest,
    InvalidClient,
    InvalidGrant,
    InvalidScope,
    UnauthorizedClient,
    AccessDenied,
    ServerError,
}

impl OAuth2ErrorCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            OAuth2ErrorCode::InvalidRequest => "invalid_request",
            OAuth2ErrorCode::InvalidClient => "invalid_client",
            OAuth2ErrorCode::InvalidGrant => "invalid_grant",
            OAuth2ErrorCode::InvalidScope => "invalid_scope",
            OAuth2ErrorCode::UnauthorizedClient => "unauthorized_client",
            OAuth2ErrorCode::AccessDenied => "access_denied",
            OAuth2ErrorCode::ServerError => "server_error",
        }
    }

    fn status_code(&self) -> StatusCode {
        match self {
            OAuth2ErrorCode::InvalidRequest => StatusCode::BAD_REQUEST,
            OAuth2ErrorCode::InvalidClient => StatusCode::UNAUTHORIZED,
            OAuth2ErrorCode::InvalidGrant => StatusCode::BAD_REQUEST,
            OAuth2ErrorCode::InvalidScope => StatusCode::BAD_REQUEST,
            OAuth2ErrorCode::UnauthorizedClient => StatusCode::BAD_REQUEST,
            OAuth2ErrorCode::AccessDenied => StatusCode::FORBIDDEN,
            OAuth2ErrorCode::ServerError => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn error_code(&self) -> i32 {
        match self {
            OAuth2ErrorCode::InvalidRequest => 40001,
            OAuth2ErrorCode::InvalidClient => 40101,
            OAuth2ErrorCode::InvalidGrant => 40002,
            OAuth2ErrorCode::InvalidScope => 40003,
            OAuth2ErrorCode::UnauthorizedClient => 40004,
            OAuth2ErrorCode::AccessDenied => 40301,
            OAuth2ErrorCode::ServerError => 50001,
        }
    }
}

fn oauth_error(code: OAuth2ErrorCode, message: String) -> Response {
    let status = code.status_code();
    let num = code.error_code();
    let error_str = code.as_str();
    if matches!(code, OAuth2ErrorCode::InvalidClient) {
        (
            status,
            [(header::WWW_AUTHENTICATE, "Basic")],
            Json(OAuth2ErrorBody {
                error: error_str,
                error_description: Some(message.clone()),
            }),
        )
            .into_response()
            .with_error_info(num, message)
    } else {
        (
            status,
            Json(OAuth2ErrorBody {
                error: error_str,
                error_description: Some(message.clone()),
            }),
        )
            .into_response()
            .with_error_info(num, message)
    }
}

pub fn invalid_request(message: impl Into<String>) -> Response {
    oauth_error(OAuth2ErrorCode::InvalidRequest, message.into())
}

pub fn invalid_grant(message: impl Into<String>) -> Response {
    oauth_error(OAuth2ErrorCode::InvalidGrant, message.into())
}

pub fn invalid_client(message: impl Into<String>) -> Response {
    oauth_error(OAuth2ErrorCode::InvalidClient, message.into())
}

pub fn access_denied(message: impl Into<String>) -> Response {
    oauth_error(OAuth2ErrorCode::AccessDenied, message.into())
}

pub fn invalid_scope(message: impl Into<String>) -> Response {
    oauth_error(OAuth2ErrorCode::InvalidScope, message.into())
}

pub fn unauthorized_client(message: impl Into<String>) -> Response {
    oauth_error(OAuth2ErrorCode::UnauthorizedClient, message.into())
}

pub fn map_typed_error(e: OAuth2TypedError) -> Response {
    match &e {
        OAuth2TypedError::ClientNotFound | OAuth2TypedError::ClientMismatch => {
            invalid_client(e.to_string())
        }
        OAuth2TypedError::ClientDisabled => unauthorized_client(e.to_string()),
        OAuth2TypedError::InvalidRedirectUri
        | OAuth2TypedError::RedirectUriMismatch
        | OAuth2TypedError::InvalidOrExpiredAuthCode
        | OAuth2TypedError::InvalidOrExpiredRefreshToken
        | OAuth2TypedError::PkceVerificationFailed
        | OAuth2TypedError::MissingPkceChallenge => invalid_grant(e.to_string()),
        OAuth2TypedError::ScopeNotAllowed(_) => invalid_scope(e.to_string()),
        OAuth2TypedError::GrantTypeNotAllowed(_) => unauthorized_client(e.to_string()),
        OAuth2TypedError::MissingField(_) => invalid_request(e.to_string()),
        OAuth2TypedError::UserNotAuthenticated | OAuth2TypedError::AppDisabled => access_denied(e.to_string()),
    }
}

pub fn map_app_error(e: crate::shared::error::AppError) -> Response {
    match &e {
        crate::shared::error::AppError::BadRequest(msg) => {
            if msg.contains("client_id") || msg.contains("client mismatch") {
                return invalid_client(msg);
            }
            if msg.contains("client is disabled") {
                return unauthorized_client(msg);
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
            if msg.contains("scope") {
                return invalid_scope(msg);
            }
            if msg.contains("grant_type") {
                return unauthorized_client(msg);
            }
            invalid_request(msg)
        }
        crate::shared::error::AppError::Validation(msg) => invalid_request(msg),
        crate::shared::error::AppError::Conflict(msg) => invalid_request(msg),
        crate::shared::error::AppError::Unauthorized => invalid_client("authentication failed"),
        crate::shared::error::AppError::Forbidden(msg) => access_denied(msg),
        crate::shared::error::AppError::NotFound(_) => invalid_client(e.to_string()),
        _ => {
            tracing::error!(error = %e, "oauth2 internal error");
            oauth_error(OAuth2ErrorCode::ServerError, "server_error".to_string())
        }
    }
}
