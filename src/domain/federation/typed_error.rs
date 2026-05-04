use crate::shared::error::AppError;

#[derive(Debug, thiserror::Error)]
pub enum SocialTypedError {
    #[error("social provider not found")]
    ProviderNotFound,
    #[error("social provider is disabled")]
    ProviderDisabled,
    #[error("social login failed: {0}")]
    LoginFailed(String),
    #[error("invalid or expired social login state")]
    StateInvalid,
}

impl From<SocialTypedError> for AppError {
    fn from(e: SocialTypedError) -> AppError {
        match e {
            SocialTypedError::ProviderNotFound => AppError::NotFound("social provider".into()),
            SocialTypedError::ProviderDisabled => {
                AppError::BadRequest("social provider is disabled".into())
            }
            SocialTypedError::LoginFailed(msg) => {
                AppError::BadRequest(format!("social login failed: {msg}"))
            }
            SocialTypedError::StateInvalid => {
                AppError::BadRequest("invalid or expired social login state".into())
            }
        }
    }
}
