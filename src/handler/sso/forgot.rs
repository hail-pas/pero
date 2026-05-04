use askama::Template;
use axum::extract::State;
use axum::response::{IntoResponse, Response};

use crate::api::extractors::ValidatedForm;
use crate::application::password_reset;
use crate::domain::sso::models::ForgotPasswordForm;
use crate::handler::sso::common::render_tpl;
use crate::shared::error::AppError;
use crate::shared::state::AppState;

#[derive(Template, Debug)]
#[template(path = "sso/forgot_password.html")]
pub struct ForgotTemplate {
    pub success: bool,
}

pub async fn forgot_get() -> Result<Response, AppError> {
    render_forgot(false)
}

pub async fn forgot_post(
    State(state): State<AppState>,
    ValidatedForm(form): ValidatedForm<ForgotPasswordForm>,
) -> Result<Response, AppError> {
    password_reset::request_reset(
        &*state.repos.users,
        &*state.repos.kv,
        &form.identifier,
        state.config.sso.password_reset_ttl_seconds,
    )
    .await?;

    render_forgot(true)
}

fn render_forgot(success: bool) -> Result<Response, AppError> {
    let tpl = ForgotTemplate { success };
    Ok(render_tpl(&tpl)?.into_response())
}
