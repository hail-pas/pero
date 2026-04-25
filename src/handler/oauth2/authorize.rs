use axum::extract::State;
use axum::http::HeaderMap;
use axum::http::header;
use axum::response::{IntoResponse, Redirect, Response};
use validator::Validate;

use crate::domain::oauth2::models::AuthorizeQuery;
use crate::domain::oauth2::service;
use crate::domain::social::store::SocialProviderRepo;
use crate::domain::sso::models::{AuthorizeParams, SsoSession};
use crate::domain::sso::session::{self, get_session_id};
use crate::handler::sso::common::set_session_cookie;
use crate::shared::error::AppError;
use crate::shared::state::AppState;

pub async fn authorize(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Query(query): axum::extract::Query<AuthorizeQuery>,
) -> Result<Response, AppError> {
    query
        .validate()
        .map_err(|e: validator::ValidationErrors| AppError::Validation(e.to_string()))?;

    let client = service::load_authorization_client(&state, &query.client_id).await?;
    service::ensure_redirect_uri_allowed(&client, &query.redirect_uri)?;

    let requested_scopes = crate::shared::utils::parse_scopes(query.scope.as_deref());

    if let Err(err) = service::ensure_authorization_client_ready(&client, &requested_scopes) {
        return Ok(redirect_error_response(
            &query.redirect_uri,
            authorization_error_code(&err),
            query.state.as_deref(),
        )
        .into_response());
    }

    let params = AuthorizeParams {
        client_id: query.client_id,
        redirect_uri: query.redirect_uri,
        response_type: "code".into(),
        scope: query.scope,
        state: query.state,
        code_challenge: query.code_challenge,
        code_challenge_method: query.code_challenge_method.as_str().to_string(),
        nonce: query.nonce,
    };

    let existing_sid = get_session_id(&headers);
    if let Some(sid) = existing_sid {
        if let Some(mut existing) = session::get(&state.cache, &sid).await? {
            if existing.authenticated && existing.user_id.is_some() {
                existing.authorize_params = params;
                session::update(
                    &state.cache,
                    &sid,
                    &existing,
                    state.config.sso.session_ttl_seconds,
                )
                .await?;
                return Ok(Redirect::to("/sso/consent").into_response());
            }
        }
    }

    let sso = SsoSession {
        authorize_params: params,
        user_id: None,
        authenticated: false,
        auth_time: None,
    };

    let session_id =
        session::create(&state.cache, &sso, state.config.sso.session_ttl_seconds).await?;

    if let Some(ref hint) = query.login_hint {
        if SocialProviderRepo::find_enabled_by_name(&state.db, hint)
            .await?
            .is_some()
        {
            let mut response = Redirect::to(&format!("/sso/social/{}/login", hint)).into_response();
            response.headers_mut().append(
                header::SET_COOKIE,
                set_session_cookie(&state.config.sso, &session_id)?,
            );
            return Ok(response);
        }
    }

    let mut response = Redirect::to("/sso/login").into_response();
    response.headers_mut().append(
        header::SET_COOKIE,
        set_session_cookie(&state.config.sso, &session_id)?,
    );
    Ok(response)
}

fn redirect_error_response(redirect_uri: &str, error: &str, state: Option<&str>) -> Redirect {
    let mut location = format!("{redirect_uri}?error={error}");
    if let Some(state) = state {
        location.push_str("&state=");
        location.push_str(&urlencoding::encode(state));
    }
    Redirect::to(&location)
}

fn authorization_error_code(err: &AppError) -> &'static str {
    match err {
        AppError::Forbidden(_) => "access_denied",
        AppError::BadRequest(message) if message.contains("scope") => "invalid_scope",
        AppError::BadRequest(message) if message.contains("grant_type") => "unauthorized_client",
        AppError::BadRequest(message) if message.contains("client") => "unauthorized_client",
        _ => "invalid_request",
    }
}
