use crate::shared::error::AppError;

pub fn hash_secret(secret: &str) -> Result<String, AppError> {
    bcrypt::hash(secret, bcrypt::DEFAULT_COST)
        .map_err(|e| AppError::Internal(format!("Secret hash error: {e}")))
}

pub fn verify_secret(secret: &str, hash: &str) -> Result<bool, AppError> {
    bcrypt::verify(secret, hash)
        .map_err(|e| AppError::Internal(format!("Secret verify error: {e}")))
}
