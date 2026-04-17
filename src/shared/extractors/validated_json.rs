use crate::shared::error::AppError;
use axum::Json;
use axum::body::Body;
use axum::extract::FromRequest;
use axum::http::Request;
use validator::Validate;

pub struct ValidatedJson<T>(pub T);

fn validate<T: Validate>(value: T) -> Result<T, AppError> {
    value
        .validate()
        .map_err(|e: validator::ValidationErrors| AppError::Validation(e.to_string()))?;
    Ok(value)
}

impl<T, S> FromRequest<S> for ValidatedJson<T>
where
    T: serde::de::DeserializeOwned + Validate,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request(req: Request<Body>, state: &S) -> Result<Self, Self::Rejection> {
        let Json(value) = Json::<T>::from_request(req, state)
            .await
            .map_err(|e| AppError::Validation(e.to_string()))?;
        Ok(ValidatedJson(validate(value)?))
    }
}
