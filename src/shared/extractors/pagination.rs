use crate::shared::error::AppError;
use axum::extract::{FromRequestParts, Query};
use axum::http::request::Parts;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Pagination {
    #[serde(default = "default_page")]
    pub page: i64,
    #[serde(default = "default_page_size")]
    pub page_size: i64,
}

fn default_page() -> i64 {
    1
}
fn default_page_size() -> i64 {
    10
}

const MAX_PAGE_SIZE: i64 = 100;

impl<S: Send + Sync> FromRequestParts<S> for Pagination {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let Query(mut pag) = Query::<Pagination>::from_request_parts(parts, _state)
            .await
            .map_err(|e| AppError::BadRequest(e.to_string()))?;

        if pag.page < 1 {
            pag.page = 1;
        }
        if pag.page_size < 1 {
            pag.page_size = default_page_size();
        }
        if pag.page_size > MAX_PAGE_SIZE {
            pag.page_size = MAX_PAGE_SIZE;
        }
        Ok(pag)
    }
}
