use http::StatusCode;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OidcErrorCode {
    InteractionRequired,
    LoginRequired,
    AccountSelectionRequired,
    ConsentRequired,
    InvalidRequestUri,
    InvalidRequestObject,
    RequestNotSupported,
    RequestUriNotSupported,
    RegistrationNotSupported,
}

impl OidcErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InteractionRequired => "interaction_required",
            Self::LoginRequired => "login_required",
            Self::AccountSelectionRequired => "account_selection_required",
            Self::ConsentRequired => "consent_required",
            Self::InvalidRequestUri => "invalid_request_uri",
            Self::InvalidRequestObject => "invalid_request_object",
            Self::RequestNotSupported => "request_not_supported",
            Self::RequestUriNotSupported => "request_uri_not_supported",
            Self::RegistrationNotSupported => "registration_not_supported",
        }
    }
}

#[derive(Debug, Clone)]
pub struct OidcError {
    pub code: OidcErrorCode,
    pub description: Option<String>,
    pub error_uri: Option<String>,
    pub state: Option<String>,
    pub status: StatusCode,
}

impl OidcError {
    pub fn new(code: OidcErrorCode) -> Self {
        Self {
            code,
            description: None,
            error_uri: None,
            state: None,
            status: StatusCode::BAD_REQUEST,
        }
    }

    pub fn login_required(description: impl Into<String>) -> Self {
        Self::new(OidcErrorCode::LoginRequired).with_description(description)
    }

    pub fn consent_required(description: impl Into<String>) -> Self {
        Self::new(OidcErrorCode::ConsentRequired).with_description(description)
    }

    pub fn interaction_required(description: impl Into<String>) -> Self {
        Self::new(OidcErrorCode::InteractionRequired).with_description(description)
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

    pub fn response_body(&self) -> OidcErrorResponse {
        OidcErrorResponse {
            error: self.code.as_str().to_owned(),
            error_description: self.description.clone(),
            error_uri: self.error_uri.clone(),
            state: self.state.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcErrorResponse {
    pub error: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_uri: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
}
