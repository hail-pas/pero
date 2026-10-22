use crate::{
    app::AppError,
    protocol::{OAuth2Error, OidcError, SamlError},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SsoProtocol {
    OAuth2,
    Oidc,
    Saml2,
}

impl SsoProtocol {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::OAuth2 => "oauth2",
            Self::Oidc => "oidc",
            Self::Saml2 => "saml2",
        }
    }
}

#[derive(Debug, Clone)]
pub struct SsoError {
    pub protocol: SsoProtocol,
    pub code: String,
    pub message: String,
    pub provider: Option<String>,
    pub correlation_id: Option<String>,
}

impl SsoError {
    pub fn new(protocol: SsoProtocol, code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            protocol,
            code: code.into(),
            message: message.into(),
            provider: None,
            correlation_id: None,
        }
    }

    pub fn with_provider(mut self, provider: impl Into<String>) -> Self {
        self.provider = Some(provider.into());
        self
    }

    pub fn with_correlation_id(mut self, correlation_id: impl Into<String>) -> Self {
        self.correlation_id = Some(correlation_id.into());
        self
    }
}

impl From<SsoError> for AppError {
    fn from(value: SsoError) -> Self {
        let mut err = AppError::bad_request(
            format!("sso.{}.{}", value.protocol.as_str(), value.code),
            value.message,
        );

        if let Some(provider) = value.provider {
            err = err.with_extension("sso_provider", provider);
        }

        if let Some(correlation_id) = value.correlation_id {
            err = err.with_extension("sso_correlation_id", correlation_id);
        }

        err
    }
}

impl From<OAuth2Error> for SsoError {
    fn from(value: OAuth2Error) -> Self {
        Self::new(
            SsoProtocol::OAuth2,
            value.code.as_str(),
            value
                .description
                .unwrap_or_else(|| value.code.as_str().to_owned()),
        )
    }
}

impl From<OidcError> for SsoError {
    fn from(value: OidcError) -> Self {
        Self::new(
            SsoProtocol::Oidc,
            value.code.as_str(),
            value
                .description
                .unwrap_or_else(|| value.code.as_str().to_owned()),
        )
    }
}

impl From<SamlError> for SsoError {
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

        Self::new(
            SsoProtocol::Saml2,
            code,
            value.message.unwrap_or_else(|| "SAML2 error".to_owned()),
        )
    }
}
