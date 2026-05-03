use askama::Template;
use axum::extract::{Query, State};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

use crate::api::extractors::ValidatedForm;
use crate::domain::sso::models::ResetPasswordForm;
use crate::handler::sso::common::render_tpl;
use crate::shared::constants::cache_keys::PASSWORD_RESET_PREFIX;
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
    let valid = validate_token(&state, &token).await.is_some();

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

    let user_id = consume_token(&state, &token)
        .await
        .ok_or_else(|| AppError::BadRequest("Invalid or expired reset token.".into()))?;

    let user = state.repos.users.find_by_id(user_id)
        .await?
        .ok_or_else(|| AppError::Unauthorized)?;
    if !user.is_active() {
        return Err(AppError::Unauthorized);
    }

    let hash = crate::shared::crypto::hash_secret(&form.new_password)?;
    state.repos.identities.update_credential(user_id, "password", &hash).await?;

    state.repos.sessions.revoke_all_for_user(user_id).await?;
    state.repos.oauth2_tokens.revoke_all_for_user(user_id).await?;

    let tpl = ResetPasswordTemplate {
        token: String::new(),
        valid: false,
        error: String::new(),
        success: "password_reset".into(),
    };
    Ok(render_tpl(&tpl)?.into_response())
}

async fn validate_token(state: &AppState, token: &str) -> Option<uuid::Uuid> {
    let uid_str: String =
        crate::shared::utils::validate_cached_token(&*state.repos.kv, PASSWORD_RESET_PREFIX, token)
            .await?;
    uid_str.parse().ok()
}

async fn consume_token(state: &AppState, token: &str) -> Option<uuid::Uuid> {
    let uid_str: String =
        crate::shared::utils::consume_cached_token(&*state.repos.kv, PASSWORD_RESET_PREFIX, token)
            .await?;
    uid_str.parse().ok()
}
