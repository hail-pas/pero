use crate::shared::error::AppError;

#[derive(Debug, thiserror::Error)]
pub enum OAuth2TypedError {
    #[error("oauth2 client not found")]
    ClientNotFound,
    #[error("client is disabled")]
    ClientDisabled,
    #[error("invalid redirect_uri")]
    InvalidRedirectUri,
    #[error("scope '{0}' not allowed")]
    ScopeNotAllowed(String),
    #[error("grant_type '{0}' not allowed")]
    GrantTypeNotAllowed(String),
    #[error("invalid or expired authorization code")]
    InvalidOrExpiredAuthCode,
    #[error("invalid or expired refresh token")]
    InvalidOrExpiredRefreshToken,
    #[error("client mismatch")]
    ClientMismatch,
    #[error("PKCE verification failed")]
    PkceVerificationFailed,
    #[error("authorization code has no PKCE challenge")]
    MissingPkceChallenge,
    #[error("redirect_uri mismatch")]
    RedirectUriMismatch,
    #[error("missing {0}")]
    MissingField(&'static str),
    #[error("user not authenticated")]
    UserNotAuthenticated,
    #[error("app is disabled")]
    AppDisabled,
}

impl From<OAuth2TypedError> for AppError {
    fn from(e: OAuth2TypedError) -> AppError {
        match e {
            OAuth2TypedError::ClientNotFound => AppError::NotFound("oauth2 client".into()),
            OAuth2TypedError::ClientDisabled => AppError::Forbidden("client is disabled".into()),
            OAuth2TypedError::InvalidRedirectUri => AppError::BadRequest("invalid redirect_uri".into()),
            OAuth2TypedError::ScopeNotAllowed(s) => AppError::BadRequest(format!("scope '{}' not allowed", s)),
            OAuth2TypedError::GrantTypeNotAllowed(gt) => AppError::BadRequest(format!("grant_type '{}' not allowed", gt)),
            OAuth2TypedError::InvalidOrExpiredAuthCode => AppError::BadRequest("invalid or expired authorization code".into()),
            OAuth2TypedError::InvalidOrExpiredRefreshToken => AppError::BadRequest("invalid or expired refresh token".into()),
            OAuth2TypedError::ClientMismatch => AppError::BadRequest("client mismatch".into()),
            OAuth2TypedError::PkceVerificationFailed => AppError::BadRequest("PKCE verification failed".into()),
            OAuth2TypedError::MissingPkceChallenge => AppError::BadRequest("authorization code has no PKCE challenge".into()),
            OAuth2TypedError::RedirectUriMismatch => AppError::BadRequest("redirect_uri mismatch".into()),
            OAuth2TypedError::MissingField(name) => AppError::BadRequest(format!("missing {}", name)),
            OAuth2TypedError::UserNotAuthenticated => AppError::Forbidden("user not authenticated".into()),
            OAuth2TypedError::AppDisabled => AppError::Forbidden("app is disabled".into()),
        }
    }
}
