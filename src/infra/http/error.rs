use axum::Json;
use axum::response::{IntoResponse, Response};

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

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
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
