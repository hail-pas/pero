use askama::Template;
use axum::Form;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Redirect, Response};

use crate::domain::sso::models::ConsentAction;
use crate::domain::sso::service;
use crate::handler::sso::common::{
    clear_session_cookie, render_tpl, require_authenticated_sso_session,
};
use crate::handler::sso::login::query_from_session;
use crate::shared::error::AppError;
use crate::shared::state::AppState;

#[derive(Template, Debug)]
#[template(path = "sso/consent.html")]
pub struct ConsentTemplate {
    pub client_name: String,
    pub scopes: Vec<String>,
    pub error: Option<String>,
    pub query_params: String,
}

pub async fn consent_get(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let (_sid, sso) = match require_authenticated_sso_session(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return Ok(response),
    };

    let consent = service::build_consent_view(&state, &sso).await?;
    let tpl = ConsentTemplate {
        client_name: consent.client_name,
        scopes: consent.scopes,
        error: None,
        query_params: query_from_session(&sso),
    };
    Ok(render_tpl(&tpl)?.into_response())
}

pub async fn consent_post(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(action): Form<ConsentAction>,
) -> Result<Response, AppError> {
    let (sid, sso) = match require_authenticated_sso_session(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return Ok(response),
    };

    let redirect = service::handle_consent_action(&state, &sid, &sso, action.action).await?;
    let mut response = Redirect::to(&redirect).into_response();
    response.headers_mut().append(
        axum::http::header::SET_COOKIE,
        clear_session_cookie(&state.config.sso)?,
    );
    Ok(response)
}
