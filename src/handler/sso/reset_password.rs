use askama::Template;
use axum::extract::{Query, State};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

use crate::api::extractors::ValidatedForm;
use crate::application::password_reset;
use crate::domain::sso::models::ResetPasswordForm;
use crate::handler::sso::common::render_tpl;
use crate::shared::error::AppError;
use crate::shared::state::AppState;

#[derive(Debug, Deserialize)]
pub struct TokenQuery {
    pub token: Option<String>,
}

#[derive(Template, Debug)]
#[template(path = "sso/reset_password.html")]
pub struct ResetPasswordTemplate {
    pub token: String,
    pub valid: bool,
    pub error: String,
    pub success: String,
}

pub async fn reset_password_get(
    State(state): State<AppState>,
    Query(query): Query<TokenQuery>,
) -> Result<Response, AppError> {
    let token = query.token.unwrap_or_default();
    let valid = password_reset::validate_reset_token(&*state.repos.kv, &token)
        .await
        .is_some();

    let error = if token.is_empty() || !valid {
        "invalid_token".into()
    } else {
        String::new()
    };
    let tpl = ResetPasswordTemplate {
        token: token.clone(),
        valid,
        error,
        success: String::new(),
    };
    Ok(render_tpl(&tpl)?.into_response())
}

pub async fn reset_password_post(
    State(state): State<AppState>,
    Query(query): Query<TokenQuery>,
    ValidatedForm(form): ValidatedForm<ResetPasswordForm>,
) -> Result<Response, AppError> {
    let token = query.token.unwrap_or_default();

    if form.new_password != form.confirm_password {
        let tpl = ResetPasswordTemplate {
            token,
            valid: true,
            error: "password_mismatch".into(),
            success: String::new(),
        };
        return Ok(render_tpl(&tpl)?.into_response());
    }

    password_reset::complete_reset(
        &*state.repos.users,
        &*state.repos.identities,
        &*state.repos.sessions,
        &*state.repos.refresh_tokens,
        &*state.repos.kv,
        &token,
        &form.new_password,
    )
    .await?;

    let tpl = ResetPasswordTemplate {
        token: String::new(),
        valid: false,
        error: String::new(),
        success: "password_reset".into(),
    };
    Ok(render_tpl(&tpl)?.into_response())
}
