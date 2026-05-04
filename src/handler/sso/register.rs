use askama::Template;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Redirect, Response};

use crate::api::extractors::ValidatedForm;
use crate::application::sso_login;
use crate::domain::sso::models::RegisterForm;
use crate::handler::sso::common::{load_sso_session, render_tpl, set_account_cookie};
use crate::shared::error::AppError;
use crate::shared::state::AppState;

#[derive(Template, Debug)]
#[template(path = "sso/register.html")]
pub struct RegisterTemplate {
    pub error: String,
}

pub async fn register_get(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let (_sid, _sso) = match load_sso_session(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return Ok(response),
    };
    let tpl = RegisterTemplate {
        error: String::new(),
    };
    Ok(render_tpl(&tpl)?.into_response())
}

pub async fn register_post(
    State(state): State<AppState>,
    headers: HeaderMap,
    ValidatedForm(form): ValidatedForm<RegisterForm>,
) -> Result<Response, AppError> {
    let (sid, mut sso) = match load_sso_session(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return Ok(response),
    };

    let user = match sso_login::register_and_authenticate(
        &*state.repos.users,
        &*state.repos.identities,
        &*state.repos.sso_sessions,
        &sid,
        &mut sso,
        &form,
        state.config.sso.session_ttl_seconds,
    )
    .await
    {
        Ok(user) => user,
        Err(AppError::Conflict(msg)) => {
            let tpl = RegisterTemplate { error: msg };
            return Ok(render_tpl(&tpl)?.into_response());
        }
        Err(e) => return Err(e),
    };

    let mut response = Redirect::to("/sso/consent").into_response();
    response.headers_mut().append(
        axum::http::header::SET_COOKIE,
        set_account_cookie(&state, user.id, &headers).await?,
    );
    Ok(response)
}
