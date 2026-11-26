use axum::extract::State;
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::cookie::CookieJar;
use pero_api_axum::extractor::ClientIp;

use crate::state::app::AppState;
use crate::web::login_flow::{LoginFormError, authenticate_password_form};
use crate::web::session::extract_browser_session;
use crate::web::sso::dto::{AccountLoginView, LoginForm};
use crate::web::sso::{register, utility::find_enabled_social_providers};
use crate::web::util::safe_redirect;

/// EP-18: GET /account/login
pub async fn get(
    State(state): State<AppState>,
    jar: CookieJar,
    axum::extract::Query(query): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Response {
    let redirect = safe_redirect(query.get("redirect").map_or("", String::as_str));
    if redirect == "/sso/register"
        && !register::flow_matches(&state, &jar, query.get("flow").map(String::as_str))
    {
        return Redirect::to("/sso/register?error=enrollment_flow_changed").into_response();
    }

    if let Some(session) = match extract_browser_session(&state, &jar).await {
        Ok(session) => session,
        Err(status) => return status.into_response(),
    } && !session.recovery_pending
        && (!session.mfa_required || session.mfa_verified_at.is_some())
    {
        return Redirect::to(&redirect).into_response();
    }

    render(
        &state,
        jar,
        query.get("error").map_or("", String::as_str),
        &redirect,
    )
    .await
}

/// EP-19: POST /account/login
pub async fn post(
    State(state): State<AppState>,
    jar: CookieJar,
    ClientIp(ip): ClientIp,
    headers: axum::http::HeaderMap,
    axum::Form(form): axum::Form<LoginForm>,
) -> Response {
    let redirect = safe_redirect(&form.redirect);
    if redirect == "/sso/register" && !register::flow_matches(&state, &jar, form.flow.as_deref()) {
        return crate::web::util::management_response(Err(
            crate::service::ManagementError::Invalid("enrollment_flow_changed"),
        ));
    }

    let token = match authenticate_password_form(
        &state,
        &jar,
        ip,
        &form,
        crate::web::util::user_agent(&headers),
    )
    .await
    {
        Ok(token) => token,
        Err(LoginFormError::ServiceUnavailable) => {
            return axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
        Err(LoginFormError::Internal) => {
            return axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
        Err(error) => {
            let key = error.message_key().unwrap_or("invalid_credentials");
            return render(&state, jar, key, &redirect).await;
        }
    };

    crate::web::login_flow::finish_login(&state, jar, &token, &redirect).await
}

async fn render(state: &AppState, jar: CookieJar, error: &str, redirect: &str) -> Response {
    let flow = (redirect == "/sso/register").then(|| register::flow_binding(state, &jar));
    let providers = match find_enabled_social_providers(state).await {
        Ok(providers) => providers,
        Err(error) => return crate::web::util::dependency_error(error),
    };
    state
        .web_security()
        .view_with_csrf(jar, "AccountLoginView", |csrf_token| AccountLoginView {
            error: error.to_owned(),
            providers,
            csrf_token,
            redirect: redirect.to_owned(),
            flow,
        })
}
