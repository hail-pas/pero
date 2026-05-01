use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;

use crate::domain::social::service;
use crate::domain::sso::session;
use crate::handler::social::social_callback_url;
use crate::handler::sso::common::mark_sso_authenticated;
use crate::shared::error::AppError;
use crate::shared::state::AppState;

#[derive(Debug, Deserialize)]
pub struct CallbackQuery {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
    pub error_description: Option<String>,
    pub bind_user: Option<String>,
}

pub async fn social_callback(
    State(state): State<AppState>,
    Path(provider): Path<String>,
    Query(query): Query<CallbackQuery>,
) -> Result<Response, AppError> {
    if let Some(error) = query.error {
        let msg = query.error_description.as_deref().unwrap_or(&error);
        return Ok(
            Redirect::to(&format!("/sso/login?error={}", urlencoding::encode(msg))).into_response(),
        );
    }

    let code = query
        .code
        .as_deref()
        .ok_or_else(|| AppError::BadRequest("missing authorization code".into()))?;
    let state_token = query
        .state
        .as_deref()
        .ok_or_else(|| AppError::BadRequest("missing state parameter".into()))?;

    let redirect_uri = social_callback_url(&state.config.oidc.issuer, &provider);
    if let Some(bind_user_id) = query.bind_user.as_deref() {
        return handle_bind_callback(&state, code, state_token, bind_user_id).await;
    }

    let (user_info, social_state) =
        service::handle_callback(&state, code, state_token, &redirect_uri).await?;

    let sso_sid = &social_state.sso_session_id;

    if sso_sid.is_empty() {
        return Ok(Redirect::to("/sso/login?error=session_expired").into_response());
    }

    let user = service::find_or_create_user(&state, &user_info).await?;

    let mut sso = session::get(&state.cache, sso_sid)
        .await?
        .ok_or_else(|| AppError::BadRequest("SSO session expired".into()))?;

    mark_sso_authenticated(&state, sso_sid, &mut sso, user.id).await?;

    Ok(Redirect::to("/sso/consent").into_response())
}

async fn handle_bind_callback(
    state: &AppState,
    code: &str,
    state_token: &str,
    bind_user_id: &str,
) -> Result<Response, AppError> {
    service::bind_social_identity(state, code, state_token, bind_user_id).await?;

    Ok(Redirect::to("/?message=social_account_linked").into_response())
}
