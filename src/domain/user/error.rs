use crate::shared::error::AppError;

pub fn user_not_found() -> AppError {
    AppError::NotFound("user".into())
}

pub fn identity_not_found() -> AppError {
    AppError::NotFound("identity".into())
}

pub fn provider_already_bound(provider: &str) -> AppError {
    AppError::Conflict(format!("provider '{}' already bound", provider))
}

pub fn provider_binding_not_implemented(provider: &str) -> AppError {
    AppError::BadRequest(format!(
        "provider '{}' binding not yet implemented",
        provider
    ))
}

pub fn cannot_unbind_password() -> AppError {
    AppError::BadRequest("cannot unbind password identity".into())
}

pub fn must_keep_one_login_method() -> AppError {
    AppError::BadRequest("must keep at least one login method".into())
}

pub fn password_must_differ() -> AppError {
    AppError::BadRequest("new password must differ from old password".into())
}

pub fn old_password_incorrect() -> AppError {
    AppError::BadRequest("old password is incorrect".into())
}

pub fn username_exists(username: &str) -> AppError {
    AppError::Conflict(format!("username '{}' already exists", username))
}

pub fn email_exists(email: &str) -> AppError {
    AppError::Conflict(format!("email '{}' already exists", email))
}

pub fn phone_exists(phone: &str) -> AppError {
    AppError::Conflict(format!("phone '{}' already exists", phone))
}

pub fn invalid_or_expired_token() -> AppError {
    AppError::BadRequest("invalid or expired token".into())
}

pub fn email_already_verified() -> AppError {
    AppError::BadRequest("email already verified".into())
}

pub fn email_not_set() -> AppError {
    AppError::BadRequest("email not set".into())
}

pub fn phone_already_verified() -> AppError {
    AppError::BadRequest("phone already verified".into())
}

pub fn phone_not_set() -> AppError {
    AppError::BadRequest("phone number not set".into())
}
