use axum::extract::State;
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::cookie::CookieJar;
use pero_api_axum::extractor::ClientIp;

use crate::state::app::AppState;
use crate::web::login_flow::{LoginFormError, authenticate_password_form};
use crate::web::session::extract_session;
use crate::web::sso::dto::{AccountLoginView, LoginForm};
use crate::web::sso::utility::find_enabled_social_providers;
use crate::web::util::safe_redirect;

/// EP-18: GET /account/login
pub async fn get(
    State(state): State<AppState>,
    jar: CookieJar,
    axum::extract::Query(query): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Response {
    let redirect = query.get("redirect").cloned().unwrap_or_default();

    if (match extract_session(&state, &jar).await {
        Ok(session) => session,
        Err(status) => return status.into_response(),
    })
    .is_some()
    {
        return Redirect::to(&safe_redirect(&redirect)).into_response();
    }

    let providers = match find_enabled_social_providers(&state).await {
        Ok(providers) => providers,
        Err(response) => return response,
    };
    let error = query.get("error").cloned().unwrap_or_default();
    state
        .web_security()
        .view_with_csrf(jar, "AccountLoginView", |csrf_token| AccountLoginView {
            error,
            providers,
            csrf_token,
            redirect,
        })
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
            return render_error(&state, jar, key, &redirect).await;
        }
    };

    crate::web::login_flow::finish_login(&state, jar, &token, &redirect).await
}

async fn render_error(state: &AppState, jar: CookieJar, error: &str, redirect: &str) -> Response {
    let providers = match find_enabled_social_providers(state).await {
        Ok(providers) => providers,
        Err(response) => return response,
    };
    state
        .web_security()
        .view_with_csrf(jar, "AccountLoginView", |csrf_token| AccountLoginView {
            error: error.to_owned(),
            providers,
            csrf_token,
            redirect: redirect.to_owned(),
        })
}
