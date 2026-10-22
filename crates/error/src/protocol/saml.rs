use crate::{app::AppError, kind::ErrorKind};
use http::StatusCode;
use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SamlStatusCode {
    Success,
    Requester,
    Responder,
    VersionMismatch,

    AuthnFailed,
    InvalidAttrNameOrValue,
    InvalidNameIdPolicy,
    NoAuthnContext,
    NoAvailableIdp,
    NoPassive,
    NoSupportedIdp,
    PartialLogout,
    ProxyCountExceeded,
    RequestDenied,
    RequestUnsupported,
    RequestVersionDeprecated,
    RequestVersionTooHigh,
    RequestVersionTooLow,
    ResourceNotRecognized,
    TooManyResponses,
    UnknownAttrProfile,
    UnknownPrincipal,
    UnsupportedBinding,

    Other(String),
}

impl SamlStatusCode {
    pub fn as_urn(&self) -> &str {
        match self {
            Self::Success => "urn:oasis:names:tc:SAML:2.0:status:Success",
            Self::Requester => "urn:oasis:names:tc:SAML:2.0:status:Requester",
            Self::Responder => "urn:oasis:names:tc:SAML:2.0:status:Responder",
            Self::VersionMismatch => "urn:oasis:names:tc:SAML:2.0:status:VersionMismatch",

            Self::AuthnFailed => "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed",
            Self::InvalidAttrNameOrValue => {
                "urn:oasis:names:tc:SAML:2.0:status:InvalidAttrNameOrValue"
            }
            Self::InvalidNameIdPolicy => "urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy",
            Self::NoAuthnContext => "urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext",
            Self::NoAvailableIdp => "urn:oasis:names:tc:SAML:2.0:status:NoAvailableIDP",
            Self::NoPassive => "urn:oasis:names:tc:SAML:2.0:status:NoPassive",
            Self::NoSupportedIdp => "urn:oasis:names:tc:SAML:2.0:status:NoSupportedIDP",
            Self::PartialLogout => "urn:oasis:names:tc:SAML:2.0:status:PartialLogout",
            Self::ProxyCountExceeded => "urn:oasis:names:tc:SAML:2.0:status:ProxyCountExceeded",
            Self::RequestDenied => "urn:oasis:names:tc:SAML:2.0:status:RequestDenied",
            Self::RequestUnsupported => "urn:oasis:names:tc:SAML:2.0:status:RequestUnsupported",
            Self::RequestVersionDeprecated => {
                "urn:oasis:names:tc:SAML:2.0:status:RequestVersionDeprecated"
            }
            Self::RequestVersionTooHigh => {
                "urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooHigh"
            }
            Self::RequestVersionTooLow => "urn:oasis:names:tc:SAML:2.0:status:RequestVersionTooLow",
            Self::ResourceNotRecognized => {
                "urn:oasis:names:tc:SAML:2.0:status:ResourceNotRecognized"
            }
            Self::TooManyResponses => "urn:oasis:names:tc:SAML:2.0:status:TooManyResponses",
            Self::UnknownAttrProfile => "urn:oasis:names:tc:SAML:2.0:status:UnknownAttrProfile",
            Self::UnknownPrincipal => "urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal",
            Self::UnsupportedBinding => "urn:oasis:names:tc:SAML:2.0:status:UnsupportedBinding",

            Self::Other(value) => value.as_str(),
        }
    }

    pub fn is_top_level(&self) -> bool {
        matches!(
            self,
            Self::Success | Self::Requester | Self::Responder | Self::VersionMismatch
        )
    }
}

impl fmt::Display for SamlStatusCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_urn())
    }
}

impl FromStr for SamlStatusCode {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Ok(match value {
            "urn:oasis:names:tc:SAML:2.0:status:Success" => Self::Success,
            "urn:oasis:names:tc:SAML:2.0:status:Requester" => Self::Requester,
            "urn:oasis:names:tc:SAML:2.0:status:Responder" => Self::Responder,
            "urn:oasis:names:tc:SAML:2.0:status:VersionMismatch" => Self::VersionMismatch,
            "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed" => Self::AuthnFailed,
            "urn:oasis:names:tc:SAML:2.0:status:InvalidAttrNameOrValue" => {
                Self::InvalidAttrNameOrValue
            }
            "urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy" => Self::InvalidNameIdPolicy,
            "urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext" => Self::NoAuthnContext,
            "urn:oasis:names:tc:SAML:2.0:status:NoAvailableIDP" => Self::NoAvailableIdp,
            "urn:oasis:names:tc:SAML:2.0:status:NoPassive" => Self::NoPassive,
            "urn:oasis:names:tc:SAML:2.0:status:NoSupportedIDP" => Self::NoSupportedIdp,
            "urn:oasis:names:tc:SAML:2.0:status:RequestDenied" => Self::RequestDenied,
            "urn:oasis:names:tc:SAML:2.0:status:RequestUnsupported" => Self::RequestUnsupported,
            "urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal" => Self::UnknownPrincipal,
            other => Self::Other(other.to_owned()),
        })
    }
}

#[derive(Debug, Clone)]
pub struct SamlError {
    pub top_level: SamlStatusCode,
    pub second_level: Option<SamlStatusCode>,
    pub message: Option<String>,
    pub detail: Option<String>,
    pub status: StatusCode,
}

impl SamlError {
    pub fn new(top_level: SamlStatusCode) -> Self {
        debug_assert!(top_level.is_top_level());

        Self {
            top_level,
            second_level: None,
            message: None,
            detail: None,
            status: StatusCode::BAD_REQUEST,
        }
    }

    pub fn authn_failed(message: impl Into<String>) -> Self {
        Self::new(SamlStatusCode::Responder)
            .with_second_level(SamlStatusCode::AuthnFailed)
            .with_message(message)
    }

    pub fn request_denied(message: impl Into<String>) -> Self {
        Self::new(SamlStatusCode::Requester)
            .with_second_level(SamlStatusCode::RequestDenied)
            .with_message(message)
    }

    pub fn with_second_level(mut self, code: SamlStatusCode) -> Self {
        debug_assert!(!code.is_top_level());
        self.second_level = Some(code);
        self
    }

    pub fn with_message(mut self, message: impl Into<String>) -> Self {
        self.message = Some(message.into());
        self
    }

    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    pub fn status_code_urns(&self) -> Vec<&str> {
        let mut values = vec![self.top_level.as_urn()];
        if let Some(second) = &self.second_level {
            values.push(second.as_urn());
        }
        values
    }
}

impl From<SamlError> for AppError {
    fn from(value: SamlError) -> Self {
        let code = value
            .second_level
            .as_ref()
            .unwrap_or(&value.top_level)
            .as_urn()
            .rsplit(':')
            .next()
            .unwrap_or("saml_error")
            .to_ascii_lowercase();

        let mut err = AppError::new(
            match value.top_level {
                SamlStatusCode::Requester => ErrorKind::BadRequest,
                SamlStatusCode::Responder => ErrorKind::DependencyFailure,
                SamlStatusCode::VersionMismatch => ErrorKind::BadRequest,
                _ => ErrorKind::BadRequest,
            },
            format!("saml2.{code}"),
            value.message.unwrap_or_else(|| "SAML2 error".to_owned()),
        )
        .with_extension("saml_top_level_status", value.top_level.as_urn().to_owned());

        if let Some(second) = value.second_level {
            err = err.with_extension("saml_second_level_status", second.as_urn().to_owned());
        }

        if let Some(detail) = value.detail {
            err = err.with_detail(detail);
        }

        err
    }
}
