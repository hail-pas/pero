use axum::{
    extract::{FromRequestParts, Query},
    http::request::Parts,
};
use pero_types::SortRequest;
use pero_validate_core::ValidateExt;
use std::str::FromStr;

use crate::error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sort(pub SortRequest);

#[derive(Debug, serde::Deserialize)]
struct SortQuery {
    sort: Option<String>,
}

impl<S: Send + Sync> FromRequestParts<S> for Sort {
    type Rejection = error::AppErrorResponder;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let Query(query) = Query::<SortQuery>::from_request_parts(parts, state)
            .await
            .map_err(|e| error::from_bad_request("invalid_sort_params", &e.body_text()))?;

        let raw = query.sort.unwrap_or_default();

        let req = SortRequest::from_str(&raw)
            .map_err(|e| error::from_bad_request("invalid_sort_format", &e.to_string()))?;

        req.validated().map(Sort).map_err(error::from_validation)
    }
}
