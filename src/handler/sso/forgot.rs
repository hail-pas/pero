use askama::Template;
use axum::extract::State;
use axum::response::{IntoResponse, Response};

use crate::api::extractors::ValidatedForm;
use crate::domain::identity::store::UserRepo;
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
    if let Some(user) = find_user_for_reset(&state, &form.identifier).await? {
        let _token = crate::shared::utils::generate_token_and_cache(
            &state.cache,
            crate::shared::constants::cache_keys::PASSWORD_RESET_PREFIX,
            &user.id.to_string(),
            state.config.sso.password_reset_ttl_seconds,
        )
        .await?;
        tracing::info!(
            identifier = %form.identifier,
            "password reset token generated (email delivery stub)"
        );
    }

    render_forgot(true)
}

async fn find_user_for_reset(
    state: &AppState,
    identifier: &str,
) -> Result<Option<crate::domain::identity::entity::User>, AppError> {
    if identifier.contains('@') {
        UserRepo::find_by_email(&state.db, identifier).await
    } else {
        UserRepo::find_by_phone(&state.db, identifier).await
    }
}

fn render_forgot(success: bool) -> Result<Response, AppError> {
    let tpl = ForgotTemplate { success };
    Ok(render_tpl(&tpl)?.into_response())
}
