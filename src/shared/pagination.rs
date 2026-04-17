use crate::shared::error::AppError;

pub fn validate_page(page: i64, page_size: i64) -> Result<i64, AppError> {
    if page < 1 {
        return Err(AppError::BadRequest("page must be >= 1".into()));
    }
    if page_size < 1 {
        return Err(AppError::BadRequest("page_size must be >= 1".into()));
    }
    Ok((page - 1) * page_size)
}
