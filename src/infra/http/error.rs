use axum::Json;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Serialize;

use crate::api::response::ApiResponse;
use crate::shared::error::AppError;

#[derive(Clone)]
pub struct ErrorInfo {
    pub code: i32,
    pub message: String,
}

pub trait ResponseErrorExt: Sized {
    fn with_error_info(self, code: i32, message: impl Into<String>) -> Self;
}

impl ResponseErrorExt for Response {
    fn with_error_info(mut self, code: i32, message: impl Into<String>) -> Self {
        self.extensions_mut().insert(ErrorInfo {
            code,
            message: message.into(),
        });
        self
    }
}

#[derive(Debug, Serialize)]
pub struct OAuth2ErrorBody {
    pub error: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
}

fn oauth2_response(e: &crate::domain::oauth2::oauth2_error::OAuth2Error) -> Response {
    let status = StatusCode::from_u16(e.http_status()).unwrap_or(StatusCode::BAD_REQUEST);
    let error_str = e.error_code();
    let description = e.to_string();
    let body = OAuth2ErrorBody {
        error: error_str,
        error_description: Some(description.clone()),
    };
    if e.needs_www_authenticate() {
        (
            status,
            [(header::WWW_AUTHENTICATE, "Basic")],
            Json(body),
        )
            .into_response()
            .with_error_info(status.as_u16() as i32 * 100 + 1, description)
    } else {
        (status, Json(body))
            .into_response()
            .with_error_info(status.as_u16() as i32 * 100 + 1, description)
    }
}

pub fn oauth2_redirect_error_code(err: &AppError) -> &'static str {
    match err {
        AppError::OAuth2(e) => e.error_code(),
        AppError::Forbidden(_) => "access_denied",
        _ => "invalid_request",
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        match &self {
            AppError::OAuth2(e) => oauth2_response(e),
            _ => {
                let status = self.status_code();
                let message = match &self {
                    AppError::Internal(detail) => {
                        tracing::error!(internal_error = %detail, "internal server error");
                        "internal server error".to_string()
                    }
                    _ => self.to_string(),
                };
                let code = self.error_code();
                let body = ApiResponse::<()> {
                    code,
                    message: message.clone(),
                    data: None,
                };
                (status, Json(body))
                    .into_response()
                    .with_error_info(code, message)
            }
        }
    }
}
