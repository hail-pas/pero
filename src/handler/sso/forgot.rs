use askama::Template;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};

use crate::api::extractors::ValidatedForm;
use crate::domain::identity::store::UserRepo;
use crate::domain::sso::models::ForgotPasswordForm;
use crate::handler::sso::common::{load_sso_session, render_tpl};
use crate::handler::sso::login::query_from_session;
use crate::shared::error::AppError;
use crate::shared::state::AppState;

#[derive(Template, Debug)]
#[template(path = "sso/forgot.html")]
pub struct ForgotTemplate {
    pub email: String,
    pub success: Option<String>,
    pub error: Option<String>,
    pub query_params: String,
}

pub async fn forgot_get(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let (_sid, sso) = match load_sso_session(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return Ok(response),
    };
    let tpl = ForgotTemplate {
        email: String::new(),
        success: None,
        error: None,
        query_params: query_from_session(&sso),
    };
    Ok(render_tpl(&tpl)?.into_response())
}

pub async fn forgot_post(
    State(state): State<AppState>,
    headers: HeaderMap,
    ValidatedForm(form): ValidatedForm<ForgotPasswordForm>,
) -> Result<Response, AppError> {
    let (_sid, sso) = match load_sso_session(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return Ok(response),
    };
    let qp = query_from_session(&sso);

    if UserRepo::find_by_email(&state.db, &form.email)
        .await?
        .is_some()
    {
        tracing::info!(email = %form.email, "password reset requested");
    }

    let tpl = ForgotTemplate {
        email: form.email,
        success: Some("If an account with that email exists, a reset link has been sent.".into()),
        error: None,
        query_params: qp,
    };
    Ok(render_tpl(&tpl)?.into_response())
}
