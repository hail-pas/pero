use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;

use crate::domain::social::service;
use crate::domain::sso::session;
use crate::handler::social::social_callback_url;
use crate::handler::sso::common::{mark_sso_authenticated, set_account_cookie};
use crate::shared::error::AppError;
use crate::shared::state::AppState;

#[derive(Debug, Deserialize)]
pub struct CallbackQuery {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
    pub error_description: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct BindCallbackQuery {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
    pub error_description: Option<String>,
}

pub async fn social_callback(
    State(state): State<AppState>,
    Path(provider): Path<String>,
    Query(query): Query<CallbackQuery>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    if let Some(error) = query.error {
        let msg = query.error_description.as_deref().unwrap_or(&error);
        return Ok(
            crate::shared::utils::append_query_params("/sso/login", &[("error", msg)])
                .map(|u| Redirect::to(&u).into_response())
                .unwrap_or_else(|_| Redirect::to("/sso/login").into_response()),
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
    let (user_info, social_state) =
        service::handle_callback(&state, code, state_token, &provider, &redirect_uri).await?;

    let user = service::find_or_create_user(&state, &user_info).await?;

    if social_state.account_login.unwrap_or(false) {
        let cookie = set_account_cookie(&state, user.id, &headers).await?;
        let next = social_state
            .account_next
            .as_deref()
            .and_then(crate::shared::utils::safe_local_path)
            .unwrap_or_else(|| "/account/profile".to_string());
        let mut response = Redirect::to(&next).into_response();
        response
            .headers_mut()
            .append(axum::http::header::SET_COOKIE, cookie);
        let clear = axum::http::HeaderValue::from_str(
            "pero_login_next=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0",
        )
        .map_err(|e| AppError::Internal(format!("invalid cookie: {e}")))?;
        response
            .headers_mut()
            .append(axum::http::header::SET_COOKIE, clear);
        return Ok(response);
    }

    let sso_sid = &social_state.sso_session_id;

    if sso_sid.is_empty() {
        return Ok(Redirect::to("/sso/login?error=session_expired").into_response());
    }

    let mut sso = session::get(&state.cache, sso_sid)
        .await?
        .ok_or_else(|| AppError::BadRequest("SSO session expired".into()))?;

    mark_sso_authenticated(&state, sso_sid, &mut sso, user.id).await?;

    let mut response = Redirect::to("/sso/consent").into_response();
    response.headers_mut().append(
        axum::http::header::SET_COOKIE,
        set_account_cookie(&state, user.id, &headers).await?,
    );
    Ok(response)
}

pub async fn social_bind_callback(
    State(state): State<AppState>,
    Path(_provider): Path<String>,
    Query(query): Query<BindCallbackQuery>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    if let Some(error) = query.error {
        let msg = query.error_description.as_deref().unwrap_or(&error);
        return Err(AppError::BadRequest(format!("social bind failed: {msg}")));
    }

    let code = query
        .code
        .as_deref()
        .ok_or_else(|| AppError::BadRequest("missing authorization code".into()))?;
    let state_token = query
        .state
        .as_deref()
        .ok_or_else(|| AppError::BadRequest("missing state parameter".into()))?;

    let current_user_id =
        crate::handler::account::common::get_account_user_id(&state, &headers).await?;

    service::bind_social_identity(&state, code, state_token, current_user_id).await?;

    Ok(Redirect::to("/account/social").into_response())
}
