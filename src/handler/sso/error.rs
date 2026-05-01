use askama::Template;
use axum::extract::{Query, State};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

use crate::handler::sso::common::render_tpl;
use crate::shared::error::AppError;
use crate::shared::state::AppState;

#[derive(Debug, Deserialize)]
pub struct ErrorQuery {
    pub code: Option<String>,
}

#[derive(Template, Debug)]
#[template(path = "sso/error.html")]
pub struct ErrorTemplate {
    pub code: String,
}

pub async fn error_get(
    State(_state): State<AppState>,
    Query(query): Query<ErrorQuery>,
) -> Result<Response, AppError> {
    let tpl = ErrorTemplate {
        code: query.code.unwrap_or_else(|| "500".to_string()),
    };
    Ok(render_tpl(&tpl)?.into_response())
}
