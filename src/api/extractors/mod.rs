mod auth_client;
mod auth_user;
mod pagination;
mod validated_form;
mod validated_json;
mod validated_query;

use crate::shared::error::AppError;
use validator::Validate;

pub use auth_client::AuthClient;
pub use auth_user::AuthUser;
pub use pagination::Pagination;
pub use validated_form::ValidatedForm;
pub use validated_json::ValidatedJson;
pub use validated_query::ValidatedQuery;

fn validate_request<T: Validate>(value: T) -> Result<T, AppError> {
    value
        .validate()
        .map_err(|e: validator::ValidationErrors| AppError::Validation(e.to_string()))?;
    Ok(value)
}
