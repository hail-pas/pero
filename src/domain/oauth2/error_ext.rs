use crate::shared::error::AppError;

pub fn invalid_client_id() -> AppError {
    AppError::BadRequest("invalid client_id".into())
}

pub fn client_disabled() -> AppError {
    AppError::BadRequest("client is disabled".into())
}

pub fn invalid_redirect_uri() -> AppError {
    AppError::BadRequest("invalid redirect_uri".into())
}

pub fn scope_not_allowed(scope: &str) -> AppError {
    AppError::BadRequest(format!("scope '{}' not allowed", scope))
}

pub fn grant_type_not_allowed(grant_type: &str) -> AppError {
    AppError::BadRequest(format!("grant_type '{}' not allowed", grant_type))
}

pub fn invalid_or_expired_auth_code() -> AppError {
    AppError::BadRequest("invalid or expired authorization code".into())
}

pub fn invalid_or_expired_refresh_token() -> AppError {
    AppError::BadRequest("invalid or expired refresh token".into())
}

pub fn client_mismatch() -> AppError {
    AppError::BadRequest("client mismatch".into())
}

pub fn pkce_verification_failed() -> AppError {
    AppError::BadRequest("PKCE verification failed".into())
}

pub fn missing_pkce_challenge() -> AppError {
    AppError::BadRequest("authorization code has no PKCE challenge".into())
}

pub fn redirect_uri_mismatch() -> AppError {
    AppError::BadRequest("redirect_uri mismatch".into())
}

pub fn missing_field(name: &str) -> AppError {
    AppError::BadRequest(format!("missing {}", name))
}

pub fn user_not_authenticated() -> AppError {
    AppError::BadRequest("user not authenticated".into())
}
