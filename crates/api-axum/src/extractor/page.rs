use axum::{
    extract::{FromRequestParts, Query},
    http::request::Parts,
};
use pero_types::PageRequest;
use pero_validate_core::ValidateExt;

use crate::error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Page(pub PageRequest);

impl<S: Send + Sync> FromRequestParts<S> for Page {
    type Rejection = error::AppErrorResponder;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let Query(req) = Query::<PageRequest>::from_request_parts(parts, state)
            .await
            .map_err(|e| error::from_bad_request("invalid_page_params", &e.body_text()))?;

        req.validated().map(Page).map_err(error::from_validation)
    }
}
