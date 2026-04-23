use crate::shared::error::AppError;

pub fn policy_not_found() -> AppError {
    AppError::NotFound("policy".into())
}
