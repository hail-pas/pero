use crate::{app::AppError, kind::ErrorKind};
use http::StatusCode;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OAuth2ErrorCode {
    InvalidRequest,
    UnauthorizedClient,
    AccessDenied,
    UnsupportedResponseType,
    InvalidScope,
    ServerError,
    TemporarilyUnavailable,
    InvalidClient,
    InvalidGrant,
    UnsupportedGrantType,
}

impl OAuth2ErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::UnauthorizedClient => "unauthorized_client",
            Self::AccessDenied => "access_denied",
            Self::UnsupportedResponseType => "unsupported_response_type",
            Self::InvalidScope => "invalid_scope",
            Self::ServerError => "server_error",
            Self::TemporarilyUnavailable => "temporarily_unavailable",
            Self::InvalidClient => "invalid_client",
            Self::InvalidGrant => "invalid_grant",
            Self::UnsupportedGrantType => "unsupported_grant_type",
        }
    }

    pub fn default_status(self) -> StatusCode {
        match self {
            Self::InvalidClient => StatusCode::UNAUTHORIZED,
            Self::ServerError => StatusCode::INTERNAL_SERVER_ERROR,
            Self::TemporarilyUnavailable => StatusCode::SERVICE_UNAVAILABLE,
            _ => StatusCode::BAD_REQUEST,
        }
    }
}

#[derive(Debug, Clone)]
pub struct OAuth2Error {
    pub code: OAuth2ErrorCode,
    pub description: Option<String>,
    pub error_uri: Option<String>,
    pub state: Option<String>,
    pub status: StatusCode,
}

impl OAuth2Error {
    pub fn new(code: OAuth2ErrorCode) -> Self {
        Self {
            code,
            description: None,
            error_uri: None,
            state: None,
            status: code.default_status(),
        }
    }

    pub fn invalid_request(description: impl Into<String>) -> Self {
        Self::new(OAuth2ErrorCode::InvalidRequest).with_description(description)
    }

    pub fn invalid_client(description: impl Into<String>) -> Self {
        Self::new(OAuth2ErrorCode::InvalidClient).with_description(description)
    }

    pub fn invalid_grant(description: impl Into<String>) -> Self {
        Self::new(OAuth2ErrorCode::InvalidGrant).with_description(description)
    }

    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    pub fn with_error_uri(mut self, uri: impl Into<String>) -> Self {
        self.error_uri = Some(uri.into());
        self
    }

    pub fn with_state(mut self, state: impl Into<String>) -> Self {
        self.state = Some(state.into());
        self
    }

    pub fn response_body(&self) -> OAuth2ErrorResponse {
        OAuth2ErrorResponse {
            error: self.code.as_str().to_owned(),
            error_description: self.description.clone(),
            error_uri: self.error_uri.clone(),
            state: self.state.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuth2ErrorResponse {
    pub error: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_uri: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
}

impl From<OAuth2Error> for AppError {
    fn from(value: OAuth2Error) -> Self {
        let kind = match value.status {
            StatusCode::UNAUTHORIZED => ErrorKind::Unauthorized,
            StatusCode::FORBIDDEN => ErrorKind::Forbidden,
            StatusCode::SERVICE_UNAVAILABLE => ErrorKind::ServiceUnavailable,
            status if status.is_server_error() => ErrorKind::Internal,
            _ => ErrorKind::BadRequest,
        };

        let mut err = AppError::new(
            kind,
            format!("oauth2.{}", value.code.as_str()),
            value
                .description
                .clone()
                .unwrap_or_else(|| value.code.as_str().to_owned()),
        );

        if let Some(uri) = value.error_uri {
            err = err.with_extension("error_uri", uri);
        }

        if let Some(state) = value.state {
            err = err.with_extension("state", state);
        }

        err
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BearerErrorCode {
    InvalidRequest,
    InvalidToken,
    InsufficientScope,
}

impl BearerErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::InvalidToken => "invalid_token",
            Self::InsufficientScope => "insufficient_scope",
        }
    }

    pub fn default_status(self) -> StatusCode {
        match self {
            Self::InvalidRequest => StatusCode::BAD_REQUEST,
            Self::InvalidToken => StatusCode::UNAUTHORIZED,
            Self::InsufficientScope => StatusCode::FORBIDDEN,
        }
    }
}

#[derive(Debug, Clone)]
pub struct BearerError {
    pub code: BearerErrorCode,
    pub realm: Option<String>,
    pub description: Option<String>,
    pub error_uri: Option<String>,
    pub scope: Option<String>,
    pub status: StatusCode,
}

impl BearerError {
    pub fn new(code: BearerErrorCode) -> Self {
        Self {
            code,
            realm: None,
            description: None,
            error_uri: None,
            scope: None,
            status: code.default_status(),
        }
    }

    pub fn invalid_token(description: impl Into<String>) -> Self {
        Self::new(BearerErrorCode::InvalidToken).with_description(description)
    }

    pub fn insufficient_scope(scope: impl Into<String>) -> Self {
        Self::new(BearerErrorCode::InsufficientScope).with_scope(scope)
    }

    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    pub fn with_error_uri(mut self, uri: impl Into<String>) -> Self {
        self.error_uri = Some(uri.into());
        self
    }

    pub fn with_scope(mut self, scope: impl Into<String>) -> Self {
        self.scope = Some(scope.into());
        self
    }

    pub fn www_authenticate_value(&self) -> String {
        let mut parts = Vec::new();

        if let Some(realm) = &self.realm {
            parts.push(format!("realm=\"{}\"", escape_header_value(realm)));
        }

        parts.push(format!("error=\"{}\"", self.code.as_str()));

        if let Some(description) = &self.description {
            parts.push(format!(
                "error_description=\"{}\"",
                escape_header_value(description)
            ));
        }

        if let Some(uri) = &self.error_uri {
            parts.push(format!("error_uri=\"{}\"", escape_header_value(uri)));
        }

        if let Some(scope) = &self.scope {
            parts.push(format!("scope=\"{}\"", escape_header_value(scope)));
        }

        format!("Bearer {}", parts.join(", "))
    }
}

impl From<BearerError> for AppError {
    fn from(value: BearerError) -> Self {
        let kind = match value.status {
            StatusCode::UNAUTHORIZED => ErrorKind::Unauthorized,
            StatusCode::FORBIDDEN => ErrorKind::Forbidden,
            _ => ErrorKind::BadRequest,
        };

        let mut err = AppError::new(
            kind,
            format!("bearer.{}", value.code.as_str()),
            value
                .description
                .clone()
                .unwrap_or_else(|| value.code.as_str().to_owned()),
        );

        if let Some(scope) = value.scope {
            err = err.with_extension("scope", scope);
        }

        err
    }
}

fn escape_header_value(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bearer_challenge_separates_scheme_from_parameters_with_a_space() {
        assert_eq!(
            BearerError::invalid_token("Token expired").www_authenticate_value(),
            "Bearer error=\"invalid_token\", error_description=\"Token expired\""
        );
        let mut error = BearerError::insufficient_scope("profile email");
        error.realm = Some("Pero".into());
        assert_eq!(
            error.www_authenticate_value(),
            "Bearer realm=\"Pero\", error=\"insufficient_scope\", scope=\"profile email\""
        );
    }
}
