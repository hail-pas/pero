use askama::Template;
use axum::Form;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Redirect, Response};

use crate::domain::identity::session::verify_user_session;
use crate::domain::identity::store::UserRepo;
use crate::domain::sso::models::ConsentAction;
use crate::domain::sso::service;
use crate::handler::sso::common::{
    clear_session_cookie, render_tpl, require_authenticated_sso_session,
};
use crate::shared::error::AppError;
use crate::shared::state::AppState;

#[derive(Template, Debug)]
#[template(path = "sso/authorization.html")]
pub struct AuthorizationTemplate {
    pub client_name: String,
    pub client_url: String,
    pub scopes: Vec<String>,
    pub user_name: String,
    pub user_email: String,
    pub user_initial: String,
    pub user_avatar_url: String,
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
    let user = UserRepo::find_by_id(&state.db, sso.user_id.ok_or(AppError::Unauthorized)?)
        .await?
        .ok_or(AppError::Unauthorized)?;

    let tpl = AuthorizationTemplate {
        client_name: consent.client_name,
        client_url: sso.authorize_params.redirect_uri.clone(),
        scopes: consent.scopes,
        user_name: crate::handler::account::common::user_display_name(&user),
        user_email: user.email.clone().unwrap_or_default(),
        user_initial: crate::handler::account::common::user_initial(&user),
        user_avatar_url: crate::handler::account::common::user_avatar_url(&user),
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

    let account_sid = crate::shared::utils::extract_cookie(
        &headers,
        crate::shared::constants::cookies::ACCOUNT_TOKEN,
    )
    .and_then(|token| crate::infra::jwt::decode_token_claims_unverified(&token).ok())
    .and_then(|claims| claims.sid);

    if let Some(account_sid) = account_sid.as_deref() {
        verify_user_session(
            &state.cache,
            account_sid,
            sso.user_id.ok_or(AppError::Unauthorized)?
        ).await?;
    }

    let redirect =
        service::handle_consent_action(&state, &sid, &sso, action.action, account_sid.as_deref())
            .await?;
    let mut response = Redirect::to(&redirect).into_response();
    response.headers_mut().append(
        axum::http::header::SET_COOKIE,
        clear_session_cookie(&state.config.sso)?,
    );
    Ok(response)
}
