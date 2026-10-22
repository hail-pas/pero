use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use pero_error::AppError;
use std::error::Error;

use crate::response::ApiResponse;

#[derive(Debug)]
pub struct AppErrorResponder(pub AppError);

impl From<AppError> for AppErrorResponder {
    fn from(err: AppError) -> Self {
        Self(err)
    }
}

impl IntoResponse for AppErrorResponder {
    fn into_response(self) -> Response {
        let err = self.0;
        let status = err.status_code();
        let code = err.code().to_owned();
        let message = err.message().to_owned();
        let detail = err.detail().map(str::to_owned);

        if status.is_server_error() {
            tracing::error!(
                code = code,
                status = status.as_u16(),
                "{message}: {}",
                format_source_chain(err.source())
            );
        }

        let errors = {
            let issues = err.errors();
            if issues.is_empty() {
                None
            } else {
                Some(issues.to_vec())
            }
        };

        let body = crate::response::ErrorResponse {
            code: err.numeric_code(),
            message,
            detail,
            errors,
        };

        (status, axum::Json(body)).into_response()
    }
}

fn format_source_chain(mut source: Option<&dyn std::error::Error>) -> String {
    let mut parts = Vec::new();
    while let Some(err) = source {
        parts.push(err.to_string());
        source = err.source();
    }
    parts.join(" → ")
}

pub(crate) fn from_bad_request(code: &str, detail: &str) -> AppErrorResponder {
    AppError::bad_request(code, detail).into()
}

pub(crate) fn from_app_error(err: AppError) -> AppErrorResponder {
    err.into()
}

pub(crate) fn from_validation(err: pero_validate_core::ValidationError) -> AppErrorResponder {
    AppError::from(err).into()
}

impl<T: serde::Serialize> IntoResponse for ApiResponse<T> {
    fn into_response(self) -> Response {
        match self {
            ApiResponse::Success(s) => (StatusCode::OK, axum::Json(s)).into_response(),
            ApiResponse::Error(e) => {
                let status = StatusCode::from_u16((e.code / 100) as u16)
                    .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
                (status, axum::Json(e)).into_response()
            }
        }
    }
}
