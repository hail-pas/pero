use axum::http::header;
use axum::response::{IntoResponse, Response};
use serde::Serialize;

pub type ResponseEnvelope<T> = ApiResponse<T>;

pub fn json_ok() -> Response {
    axum::Json(serde_json::json!({"code": 0, "message": "ok"})).into_response()
}

pub fn json_ok_with_data(data: serde_json::Value) -> Response {
    axum::Json(serde_json::json!({
        "code": 0,
        "message": "ok",
        "data": data,
    }))
    .into_response()
}

pub fn json_ok_with_sensitive(data: serde_json::Value) -> Response {
    (
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
        axum::Json(serde_json::json!({
            "code": 0,
            "message": "ok",
            "data": data,
        })),
    )
        .into_response()
}

pub fn json_error(msg: &str) -> Response {
    (
        axum::http::StatusCode::BAD_REQUEST,
        axum::Json(serde_json::json!({"error": msg})),
    )
        .into_response()
}

pub fn json_ok_with_error(msg: &str) -> Response {
    axum::Json(serde_json::json!({"error": msg})).into_response()
}

#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum ApiResponse<T> {
    Success(SuccessResponse<T>),
    Error(ErrorResponse),
}

#[derive(Debug, Clone, Serialize)]
pub struct SuccessResponse<T> {
    pub code: u32,
    pub message: String,
    pub data: T,
}

#[derive(Debug, Clone, Serialize)]
pub struct ErrorResponse {
    pub code: u32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errors: Option<Vec<pero_validate_core::ValidationIssue>>,
}

impl<T> ApiResponse<T> {
    pub fn success(data: T) -> Self {
        Self::Success(SuccessResponse {
            code: 0,
            message: "success".to_owned(),
            data,
        })
    }

    pub fn with_message(data: T, message: impl Into<String>) -> Self {
        Self::Success(SuccessResponse {
            code: 0,
            message: message.into(),
            data,
        })
    }

    pub fn error(code: u32, message: impl Into<String>) -> Self {
        Self::Error(ErrorResponse {
            code,
            message: message.into(),
            detail: None,
            errors: None,
        })
    }

    pub fn error_with_detail(
        code: u32,
        message: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self::Error(ErrorResponse {
            code,
            message: message.into(),
            detail: Some(detail.into()),
            errors: None,
        })
    }
}
