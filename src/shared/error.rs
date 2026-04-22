use crate::shared::response::ApiResponse;
use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("{0}")]
    BadRequest(String),

    #[error("unauthorized")]
    Unauthorized,

    #[error("forbidden: {0}")]
    Forbidden(String),

    #[error("{0} not found")]
    NotFound(String),

    #[error("{0}")]
    Conflict(String),

    #[error("{0}")]
    Validation(String),

    #[error("internal server error: {0}")]
    Internal(String),
}

impl AppError {
    fn status_code(&self) -> StatusCode {
        match self {
            AppError::BadRequest(_) => StatusCode::BAD_REQUEST,
            AppError::Unauthorized => StatusCode::UNAUTHORIZED,
            AppError::Forbidden(_) => StatusCode::FORBIDDEN,
            AppError::NotFound(_) => StatusCode::NOT_FOUND,
            AppError::Conflict(_) => StatusCode::CONFLICT,
            AppError::Validation(_) => StatusCode::UNPROCESSABLE_ENTITY,
            AppError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn error_code(&self) -> i32 {
        let base = self.status_code().as_u16() as i32 * 100;
        match self {
            AppError::BadRequest(_) => base + 1,
            AppError::Unauthorized => base + 1,
            AppError::Forbidden(_) => base + 1,
            AppError::NotFound(_) => base + 1,
            AppError::Conflict(_) => base + 1,
            AppError::Validation(_) => base + 2,
            AppError::Internal(_) => base + 1,
        }
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
        let body = ApiResponse::<()> {
            code: self.error_code(),
            message,
            data: None,
        };
        (status, Json(body)).into_response()
    }
}

impl From<sqlx::Error> for AppError {
    fn from(err: sqlx::Error) -> Self {
        match &err {
            sqlx::Error::RowNotFound => AppError::NotFound("resource".into()),
            sqlx::Error::Database(db_err) => match db_err.code().as_deref() {
                Some("23505") => {
                    AppError::Conflict("duplicate key value violates unique constraint".into())
                }
                Some("23503") => AppError::BadRequest("referenced record not found".into()),
                _ => {
                    tracing::error!(error = %err, "database error");
                    AppError::Internal("database error".into())
                }
            },
            _ => {
                tracing::error!(error = %err, "database error");
                AppError::Internal("database error".into())
            }
        }
    }
}

impl From<redis::RedisError> for AppError {
    fn from(err: redis::RedisError) -> Self {
        tracing::error!(error = %err, "redis error");
        AppError::Internal("cache error".into())
    }
}
