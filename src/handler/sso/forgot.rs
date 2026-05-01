use askama::Template;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};

use crate::api::extractors::ValidatedForm;
use crate::domain::identity::store::UserRepo;
use crate::domain::sso::models::ForgotPasswordForm;
use crate::handler::sso::common::{load_sso_session, render_tpl};
use crate::shared::error::AppError;
use crate::shared::state::AppState;

#[derive(Template, Debug)]
#[template(path = "sso/forgot_password.html")]
pub struct ForgotTemplate {
    pub success: bool,
}

pub async fn forgot_get(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let (_sid, _sso) = match load_sso_session(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return Ok(response),
    };
    let tpl = ForgotTemplate { success: false };
    Ok(render_tpl(&tpl)?.into_response())
}

pub async fn forgot_post(
    State(state): State<AppState>,
    headers: HeaderMap,
    ValidatedForm(form): ValidatedForm<ForgotPasswordForm>,
) -> Result<Response, AppError> {
    let (_sid, _sso) = match load_sso_session(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return Ok(response),
    };

    let user = if form.identifier.contains('@') {
        UserRepo::find_by_email(&state.db, &form.identifier).await?
    } else {
        UserRepo::find_by_phone(&state.db, &form.identifier).await?
    };

    if let Some(user) = user {
        let token = crate::shared::utils::generate_token_and_cache(
            &state.cache,
            crate::shared::constants::cache_keys::PASSWORD_RESET_PREFIX,
            &user.id.to_string(),
            state.config.sso.password_reset_ttl_seconds,
        )
        .await?;
        tracing::info!(
            identifier = %form.identifier,
            token = %token,
            "password reset token generated (email delivery stub)"
        );
    }

    let tpl = ForgotTemplate { success: true };
    Ok(render_tpl(&tpl)?.into_response())
}
