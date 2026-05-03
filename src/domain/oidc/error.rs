use crate::shared::error::AppError;

#[derive(Debug, thiserror::Error)]
pub enum OidcError {
    #[error("invalid id token")]
    InvalidIdToken,
    #[error("audience mismatch")]
    AudienceMismatch,
    #[error("invalid post_logout_redirect_uri")]
    InvalidPostLogoutRedirectUri,
    #[error("session not found")]
    SessionNotFound,
}

impl From<OidcError> for AppError {
    fn from(e: OidcError) -> AppError {
        match e {
            OidcError::InvalidIdToken => AppError::Unauthorized,
            OidcError::AudienceMismatch => AppError::Unauthorized,
            OidcError::InvalidPostLogoutRedirectUri => AppError::BadRequest("invalid post_logout_redirect_uri".into()),
            OidcError::SessionNotFound => AppError::NotFound("session".into()),
        }
    }
}
