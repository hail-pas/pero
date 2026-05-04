use crate::shared::error::AppError;

pub fn hash_password(password: &str) -> Result<String, AppError> {
    crate::shared::crypto::hash_secret(password)
}

pub fn verify_password(password: &str, password_hash: &str) -> Result<bool, AppError> {
    crate::shared::crypto::verify_secret(password, password_hash)
}

pub fn change_password_rule(old_password: &str, new_password: &str) -> Result<(), AppError> {
    if old_password == new_password {
        return Err(crate::domain::user::error::password_must_differ());
    }
    Ok(())
}
