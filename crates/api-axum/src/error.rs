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

impl<T: serde::Serialize> IntoResponse for ApiResponse<T> {
    fn into_response(self) -> Response {
        (StatusCode::OK, axum::Json(self)).into_response()
    }
}
