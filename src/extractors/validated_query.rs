use axum::extract::{FromRequestParts, Query};
use axum::http::request::Parts;
use validator::Validate;
use crate::error::AppError;

#[allow(dead_code)]
pub struct ValidatedQuery<T>(pub T);

impl<T, S> FromRequestParts<S> for ValidatedQuery<T>
where
    T: serde::de::DeserializeOwned + Validate,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let Query(value) = Query::<T>::from_request_parts(parts, state)
            .await
            .map_err(|e| AppError::BadRequest(e.to_string()))?;

        value.validate().map_err(|e: validator::ValidationErrors| AppError::Validation(e.to_string()))?;
        Ok(ValidatedQuery(value))
    }
}
