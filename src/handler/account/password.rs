use askama::Template;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};

use crate::api::extractors::ValidatedForm;
use crate::domain::identity::authn::AuthService;
use crate::domain::sso::models::ChangePasswordForm;
use crate::handler::account::common;
use crate::handler::account::common::{user_display_name, user_initial};
use crate::shared::error::AppError;
use crate::shared::state::AppState;

#[derive(Template, Debug)]
#[template(path = "account/change_password.html")]
pub struct AccountChangePasswordTemplate {
    pub active: String,
    pub user_initial: String,
    pub user_name: String,
}

pub async fn change_password_get(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let user = common::get_account_user(&state, &headers).await?;
    let tpl = AccountChangePasswordTemplate {
        active: "change_password".into(),
        user_initial: user_initial(&user),
        user_name: user_display_name(&user),
    };
    Ok(common::render_tpl(&tpl)?.into_response())
}

pub async fn change_password_post(
    State(state): State<AppState>,
    headers: HeaderMap,
    ValidatedForm(form): ValidatedForm<ChangePasswordForm>,
) -> Result<Response, AppError> {
    let user_id = common::get_account_user_id(&state, &headers).await?;
    match AuthService::change_password(&state, user_id, &form.old_password, &form.new_password)
        .await
    {
        Ok(_) => Ok(axum::Json(crate::api::response::MessageResponse::success(
            "Password updated.",
        ))
        .into_response()),
        Err(AppError::BadRequest(message)) => Err(AppError::BadRequest(message)),
        Err(AppError::Unauthorized) => Err(AppError::BadRequest(
            "Current password is incorrect.".into(),
        )),
        Err(err) => Err(err),
    }
}
