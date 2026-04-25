use crate::shared::error::AppError;
use axum::Form;
use axum::body::Body;
use axum::extract::FromRequest;
use axum::http::Request;
use validator::Validate;

pub struct ValidatedForm<T>(pub T);

impl<T, S> FromRequest<S> for ValidatedForm<T>
where
    T: serde::de::DeserializeOwned + Validate,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request(req: Request<Body>, state: &S) -> Result<Self, Self::Rejection> {
        let Form(value) = Form::<T>::from_request(req, state)
            .await
            .map_err(|e| AppError::Validation(e.to_string()))?;
        Ok(Self(super::validate_request(value)?))
    }
}
