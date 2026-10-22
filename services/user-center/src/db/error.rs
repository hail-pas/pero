use pero_error::AppError;
use sea_orm::DbErr;

/// 将 DbErr 转换为 AppError（internal 级别，保留原始错误链）
pub fn to_app_error(e: DbErr) -> AppError {
    AppError::internal("db_error", "Database error").with_source(e)
}

/// 判断是否为 unique constraint 冲突（PostgreSQL error code 23505）
pub fn is_unique_violation(err: &DbErr) -> bool {
    let msg = err.to_string().to_lowercase();
    msg.contains("23505") || msg.contains("unique") || msg.contains("duplicate")
}
