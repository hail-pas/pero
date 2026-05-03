use axum::Json;
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Serialize;

use crate::infra::http::error::ResponseErrorExt;

#[derive(Debug, Serialize)]
pub struct OAuth2ErrorBody {
    pub error: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
}

pub fn map_app_error(e: crate::shared::error::AppError) -> Response {
    match &e {
        crate::shared::error::AppError::OAuth2(oauth2_err) => {
            let status = StatusCode::from_u16(oauth2_err.http_status()).unwrap_or(StatusCode::BAD_REQUEST);
            let error_str = oauth2_err.error_code();
            let description = oauth2_err.to_string();
            let body = OAuth2ErrorBody {
                error: error_str,
                error_description: Some(description.clone()),
            };
            if oauth2_err.needs_www_authenticate() {
                (
                    status,
                    [(header::WWW_AUTHENTICATE, "Basic")],
                    Json(body),
                )
                    .into_response()
                    .with_error_info(status.as_u16() as i32 * 100 + 1, description)
            } else {
                (status, Json(body))
                    .into_response()
                    .with_error_info(status.as_u16() as i32 * 100 + 1, description)
            }
        }
        _ => e.into_response(),
    }
}
