use axum::{
    extract::{
        Form, FromRequest, FromRequestParts, Json, Query,
        rejection::{FormRejection, JsonRejection},
    },
    http::{Request, StatusCode, request::Parts},
};
use pero_error::{AppError, ErrorKind};
use pero_validate_core::ValidateExt;

use crate::error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ValidatedJson<T>(pub T);

impl<T, S> FromRequest<S> for ValidatedJson<T>
where
    T: serde::de::DeserializeOwned + pero_validate_core::Validatable,
    S: Send + Sync,
{
    type Rejection = error::AppErrorResponder;

    async fn from_request(
        req: Request<axum::body::Body>,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        let Json(value) = Json::<T>::from_request(req, state)
            .await
            .map_err(invalid_json_error)?;

        value
            .validated()
            .map(ValidatedJson)
            .map_err(error::from_validation)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ValidatedForm<T>(pub T);

impl<T, S> FromRequest<S> for ValidatedForm<T>
where
    T: serde::de::DeserializeOwned + pero_validate_core::Validatable,
    S: Send + Sync,
{
    type Rejection = error::AppErrorResponder;

    async fn from_request(
        req: Request<axum::body::Body>,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        let Form(value) = Form::<T>::from_request(req, state)
            .await
            .map_err(invalid_form_error)?;

        value
            .validated()
            .map(ValidatedForm)
            .map_err(error::from_validation)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ValidatedQuery<T>(pub T);

impl<T, S> FromRequestParts<S> for ValidatedQuery<T>
where
    T: serde::de::DeserializeOwned + pero_validate_core::Validatable,
    S: Send + Sync,
{
    type Rejection = error::AppErrorResponder;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let Query(value) = Query::<T>::from_request_parts(parts, state)
            .await
            .map_err(|e| error::from_bad_request("invalid_query", &e.body_text()))?;

        value
            .validated()
            .map(ValidatedQuery)
            .map_err(error::from_validation)
    }
}

fn invalid_json_error(err: JsonRejection) -> error::AppErrorResponder {
    invalid_body_error(
        err.status(),
        "invalid_json",
        "Invalid request body",
        err.body_text(),
    )
}

fn invalid_form_error(err: FormRejection) -> error::AppErrorResponder {
    invalid_body_error(
        err.status(),
        "invalid_form",
        "Invalid form data",
        err.body_text(),
    )
}

fn invalid_body_error(
    status: StatusCode,
    code: &'static str,
    message: &'static str,
    detail: String,
) -> error::AppErrorResponder {
    error::from_app_error(
        AppError::new(error_kind_from_status(status), code, message).with_detail(detail),
    )
}

fn error_kind_from_status(status: StatusCode) -> ErrorKind {
    match status {
        StatusCode::PAYLOAD_TOO_LARGE => ErrorKind::PayloadTooLarge,
        StatusCode::UNSUPPORTED_MEDIA_TYPE => ErrorKind::UnsupportedMediaType,
        _ => ErrorKind::BadRequest,
    }
}
