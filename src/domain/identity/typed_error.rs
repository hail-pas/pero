use crate::shared::error::AppError;

#[derive(Debug, thiserror::Error)]
pub enum IdentityTypedError {
    #[error("user not found")]
    UserNotFound,
    #[error("identity not found")]
    IdentityNotFound,
    #[error("provider '{0}' already bound")]
    ProviderAlreadyBound(String),
    #[error("cannot unbind password identity")]
    CannotUnbindPassword,
    #[error("must keep at least one login method")]
    MustKeepOneLoginMethod,
    #[error("new password must differ from old password")]
    PasswordMustDiffer,
    #[error("old password is incorrect")]
    OldPasswordIncorrect,
    #[error("username '{0}' already exists")]
    UsernameExists(String),
    #[error("email '{0}' already exists")]
    EmailExists(String),
    #[error("phone '{0}' already exists")]
    PhoneExists(String),
    #[error("invalid or expired token")]
    InvalidOrExpiredToken,
    #[error("email already verified")]
    EmailAlreadyVerified,
    #[error("email not set")]
    EmailNotSet,
    #[error("phone already verified")]
    PhoneAlreadyVerified,
    #[error("phone number not set")]
    PhoneNotSet,
}

impl From<IdentityTypedError> for AppError {
    fn from(e: IdentityTypedError) -> AppError {
        match e {
            IdentityTypedError::UserNotFound => AppError::NotFound("user".into()),
            IdentityTypedError::IdentityNotFound => AppError::NotFound("identity".into()),
            IdentityTypedError::ProviderAlreadyBound(p) => AppError::Conflict(format!("provider '{}' already bound", p)),
            IdentityTypedError::CannotUnbindPassword => AppError::BadRequest("cannot unbind password identity".into()),
            IdentityTypedError::MustKeepOneLoginMethod => AppError::BadRequest("must keep at least one login method".into()),
            IdentityTypedError::PasswordMustDiffer => AppError::BadRequest("new password must differ from old password".into()),
            IdentityTypedError::OldPasswordIncorrect => AppError::BadRequest("old password is incorrect".into()),
            IdentityTypedError::UsernameExists(u) => AppError::Conflict(format!("username '{}' already exists", u)),
            IdentityTypedError::EmailExists(e) => AppError::Conflict(format!("email '{}' already exists", e)),
            IdentityTypedError::PhoneExists(p) => AppError::Conflict(format!("phone '{}' already exists", p)),
            IdentityTypedError::InvalidOrExpiredToken => AppError::BadRequest("invalid or expired token".into()),
            IdentityTypedError::EmailAlreadyVerified => AppError::BadRequest("email already verified".into()),
            IdentityTypedError::EmailNotSet => AppError::BadRequest("email not set".into()),
            IdentityTypedError::PhoneAlreadyVerified => AppError::BadRequest("phone already verified".into()),
            IdentityTypedError::PhoneNotSet => AppError::BadRequest("phone number not set".into()),
        }
    }
}
