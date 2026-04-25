use askama::Template;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};

use crate::api::extractors::ValidatedForm;
use crate::domain::identity::authn::AuthService;
use crate::domain::sso::models::ChangePasswordForm;
use crate::handler::sso::common::{render_tpl, require_authenticated_sso_session};
use crate::handler::sso::login::query_from_session;
use crate::shared::error::AppError;
use crate::shared::state::AppState;

#[derive(Template, Debug)]
#[template(path = "sso/change_password.html")]
pub struct ChangePasswordTemplate {
    pub error: Option<String>,
    pub success: Option<String>,
    pub query_params: String,
}

pub async fn change_password_get(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let (_sid, sso) = match require_authenticated_sso_session(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return Ok(response),
    };

    let tpl = ChangePasswordTemplate {
        error: None,
        success: None,
        query_params: query_from_session(&sso),
    };
    Ok(render_tpl(&tpl)?.into_response())
}

pub async fn change_password_post(
    State(state): State<AppState>,
    headers: HeaderMap,
    ValidatedForm(form): ValidatedForm<ChangePasswordForm>,
) -> Result<Response, AppError> {
    let (_sid, sso) = match require_authenticated_sso_session(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return Ok(response),
    };

    let user_id = sso
        .user_id
        .ok_or(AppError::BadRequest("no user in session".into()))?;
    let qp = query_from_session(&sso);
    if let Err(err) =
        AuthService::change_password(&state, user_id, &form.old_password, &form.new_password).await
    {
        let message = match err {
            AppError::BadRequest(message) => message,
            AppError::Unauthorized => "invalid credentials".to_string(),
            other => return Err(other),
        };
        let tpl = ChangePasswordTemplate {
            error: Some(message),
            success: None,
            query_params: qp,
        };
        return Ok(render_tpl(&tpl)?.into_response());
    }

    let tpl = ChangePasswordTemplate {
        error: None,
        success: Some("Password updated successfully.".into()),
        query_params: qp,
    };
    Ok(render_tpl(&tpl)?.into_response())
}
