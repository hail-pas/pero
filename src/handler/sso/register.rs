use askama::Template;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Redirect, Response};

use crate::domain::identity::authn::AuthService;
use crate::domain::sso::models::RegisterForm;
use crate::handler::sso::common::{load_sso_session, render_tpl};
use crate::handler::sso::login::query_from_session;
use crate::domain::sso::session;
use crate::shared::error::AppError;
use crate::api::extractors::ValidatedForm;
use crate::shared::state::AppState;

#[derive(Template, Debug)]
#[template(path = "sso/register.html")]
pub struct RegisterTemplate {
    pub client_name: Option<String>,
    pub username: String,
    pub email: String,
    pub nickname: String,
    pub phone: String,
    pub error: Option<String>,
    pub query_params: String,
}

pub async fn register_get(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let (_sid, sso) = match load_sso_session(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return Ok(response),
    };
    let tpl = RegisterTemplate {
        client_name: None,
        username: String::new(),
        email: String::new(),
        nickname: String::new(),
        phone: String::new(),
        error: None,
        query_params: query_from_session(&sso),
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
    let qp = query_from_session(&sso);

    let tpl_error = |msg: &str| -> RegisterTemplate {
        RegisterTemplate {
            client_name: None,
            username: form.username.clone(),
            email: form.email.clone(),
            nickname: form.nickname.clone().unwrap_or_default(),
            phone: form.phone.clone().unwrap_or_default(),
            error: Some(msg.into()),
            query_params: qp.clone(),
        }
    };

    let user = match AuthService::register_user_with_password(
        &state,
        &form.username,
        &form.email,
        form.phone.as_deref(),
        form.nickname.as_deref(),
        &form.password,
    )
    .await
    {
        Ok(user) => user,
        Err(AppError::Conflict(msg)) => {
            return Ok(render_tpl(&tpl_error(&msg))?.into_response());
        }
        Err(e) => return Err(e),
    };

    sso.user_id = Some(user.id);
    sso.authenticated = true;
    sso.auth_time = Some(chrono::Utc::now().timestamp());
    session::update(&state.cache, &sid, &sso, state.config.sso.session_ttl_seconds).await?;

    Ok(Redirect::to("/sso/consent").into_response())
}
