use http::StatusCode;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorKind {
    BadRequest,
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    UnprocessableEntity,
    TooManyRequests,
    Timeout,
    UnsupportedMediaType,
    PayloadTooLarge,
    DependencyFailure,
    ServiceUnavailable,
    Internal,
}

impl ErrorKind {
    pub fn status_code(self) -> StatusCode {
        match self {
            Self::BadRequest => StatusCode::BAD_REQUEST,
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::Forbidden => StatusCode::FORBIDDEN,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::Conflict => StatusCode::CONFLICT,
            Self::UnprocessableEntity => StatusCode::UNPROCESSABLE_ENTITY,
            Self::TooManyRequests => StatusCode::TOO_MANY_REQUESTS,
            Self::Timeout => StatusCode::GATEWAY_TIMEOUT,
            Self::UnsupportedMediaType => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            Self::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::DependencyFailure => StatusCode::BAD_GATEWAY,
            Self::ServiceUnavailable => StatusCode::SERVICE_UNAVAILABLE,
            Self::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    pub fn default_numeric_code(self) -> u32 {
        match self {
            Self::BadRequest => 40000,
            Self::Unauthorized => 40100,
            Self::Forbidden => 40300,
            Self::NotFound => 40400,
            Self::Conflict => 40900,
            Self::UnprocessableEntity => 42200,
            Self::TooManyRequests => 42900,
            Self::UnsupportedMediaType => 41500,
            Self::PayloadTooLarge => 41300,
            Self::Timeout => 50400,
            Self::DependencyFailure => 50200,
            Self::ServiceUnavailable => 50300,
            Self::Internal => 50000,
        }
    }

    pub fn is_server_error(self) -> bool {
        self.status_code().is_server_error()
    }
}
