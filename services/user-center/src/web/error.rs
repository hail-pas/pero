use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};

use crate::service::oauth::OAuthError as ServiceOAuthError;

#[derive(Debug)]
pub enum OAuthError {
    BadRequest(String),
    Unavailable,
    RedirectError {
        redirect_uri: String,
        error: String,
        error_description: Option<String>,
        state: Option<String>,
    },
    Internal(pero_error::AppError),
}

impl OAuthError {
    pub fn redirect(
        redirect_uri: &str,
        error: &str,
        error_description: Option<&str>,
        state: Option<&str>,
    ) -> Self {
        Self::RedirectError {
            redirect_uri: redirect_uri.to_owned(),
            error: error.to_owned(),
            error_description: error_description.map(String::from),
            state: state.map(String::from),
        }
    }
}

impl From<ServiceOAuthError> for OAuthError {
    fn from(value: ServiceOAuthError) -> Self {
        match value {
            ServiceOAuthError::InvalidRedirectUri => {
                OAuthError::BadRequest("Invalid redirect_uri".to_owned())
            }
            ServiceOAuthError::InvalidClient(msg) => OAuthError::BadRequest(msg.to_owned()),
            ServiceOAuthError::InvalidScope(_) => {
                OAuthError::BadRequest("Invalid scope".to_owned())
            }
            ServiceOAuthError::AccessDenied => OAuthError::BadRequest("Access denied".to_owned()),
            ServiceOAuthError::Internal(e) => OAuthError::Internal(e),
        }
    }
}

impl IntoResponse for OAuthError {
    fn into_response(self) -> Response {
        match self {
            OAuthError::Unavailable => StatusCode::SERVICE_UNAVAILABLE.into_response(),
            OAuthError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg).into_response(),
            OAuthError::RedirectError {
                redirect_uri,
                error,
                error_description,
                state,
            } => {
                let url = pero_utils::oauth::url::build_error_redirect_url(
                    &redirect_uri,
                    &error,
                    error_description.as_deref(),
                    state.as_deref(),
                );
                Redirect::to(&url).into_response()
            }
            OAuthError::Internal(e) => {
                tracing::error!("OAuth internal error: {:?}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response()
            }
        }
    }
}
