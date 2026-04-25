use crate::shared::error::AppError;

pub fn provider_not_found() -> AppError {
    AppError::NotFound("social provider".into())
}

pub fn provider_disabled() -> AppError {
    AppError::BadRequest("social provider is disabled".into())
}

pub fn social_login_failed(msg: &str) -> AppError {
    AppError::BadRequest(format!("social login failed: {msg}"))
}

pub fn social_state_invalid() -> AppError {
    AppError::BadRequest("invalid or expired social login state".into())
}
