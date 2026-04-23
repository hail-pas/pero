use crate::shared::error::AppError;

pub fn app_not_found() -> AppError {
    AppError::NotFound("app".into())
}

pub fn app_code_exists(code: &str) -> AppError {
    AppError::Conflict(format!("app code '{}' already exists", code))
}
