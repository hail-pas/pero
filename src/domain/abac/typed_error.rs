use crate::shared::error::AppError;

#[derive(Debug, thiserror::Error)]
pub enum AbacTypedError {
    #[error("policy not found")]
    PolicyNotFound,
}

impl From<AbacTypedError> for AppError {
    fn from(e: AbacTypedError) -> AppError {
        match e {
            AbacTypedError::PolicyNotFound => AppError::NotFound("policy".into()),
        }
    }
}
