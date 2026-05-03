use crate::shared::error::AppError;

#[derive(Debug, thiserror::Error)]
pub enum OAuth2Error {
    #[error("oauth2 client not found")]
    InvalidClient,
    #[error("invalid client credentials")]
    InvalidClientCredentials,
    #[error("client is disabled")]
    ClientDisabled,
    #[error("app is disabled")]
    AppDisabled,
    #[error("invalid redirect_uri")]
    InvalidRedirectUri,
    #[error("redirect_uri mismatch")]
    RedirectUriMismatch,
    #[error("scope '{0}' not allowed")]
    InvalidScope(String),
    #[error("grant_type '{0}' not allowed")]
    UnauthorizedClient(String),
    #[error("invalid or expired authorization code")]
    InvalidAuthCode,
    #[error("invalid or expired refresh token")]
    InvalidRefreshToken,
    #[error("client mismatch")]
    ClientMismatch,
    #[error("PKCE verification failed")]
    PkceVerificationFailed,
    #[error("authorization code has no PKCE challenge")]
    MissingPkceChallenge,
    #[error("missing {0}")]
    MissingField(String),
    #[error("user not authenticated")]
    UserNotAuthenticated,
    #[error("account is disabled")]
    AccountDisabled,
    #[error("unsupported authorization header, expected Basic")]
    InvalidAuthHeader,
    #[error("client credentials must not be provided in both header and body")]
    DuplicateCredentials,
    #[error("refresh token replay detected")]
    RefreshTokenReplay,
}

impl OAuth2Error {
    pub fn error_code(&self) -> &'static str {
        match self {
            OAuth2Error::InvalidClient
            | OAuth2Error::InvalidClientCredentials => "invalid_client",
            OAuth2Error::ClientDisabled
            | OAuth2Error::UnauthorizedClient(_) => "unauthorized_client",
            OAuth2Error::AppDisabled
            | OAuth2Error::UserNotAuthenticated
            | OAuth2Error::AccountDisabled => "access_denied",
            OAuth2Error::InvalidRedirectUri
            | OAuth2Error::RedirectUriMismatch
            | OAuth2Error::InvalidAuthCode
            | OAuth2Error::InvalidRefreshToken
            | OAuth2Error::ClientMismatch
            | OAuth2Error::PkceVerificationFailed
            | OAuth2Error::MissingPkceChallenge
            | OAuth2Error::RefreshTokenReplay => "invalid_grant",
            OAuth2Error::InvalidScope(_) => "invalid_scope",
            OAuth2Error::MissingField(_)
            | OAuth2Error::InvalidAuthHeader
            | OAuth2Error::DuplicateCredentials => "invalid_request",
        }
    }

    pub fn http_status(&self) -> u16 {
        match self {
            OAuth2Error::InvalidClient
            | OAuth2Error::InvalidClientCredentials => 401,
            OAuth2Error::AppDisabled
            | OAuth2Error::UserNotAuthenticated
            | OAuth2Error::AccountDisabled => 403,
            OAuth2Error::MissingField(_)
            | OAuth2Error::InvalidAuthHeader
            | OAuth2Error::DuplicateCredentials => 400,
            _ => 400,
        }
    }

    pub fn needs_www_authenticate(&self) -> bool {
        matches!(self, OAuth2Error::InvalidClient | OAuth2Error::InvalidClientCredentials)
    }
}

impl From<OAuth2Error> for AppError {
    fn from(e: OAuth2Error) -> AppError {
        AppError::OAuth2(e)
    }
}
