use axum::extract::State;
use axum::http::HeaderMap;
use axum::http::header;
use axum::response::{IntoResponse, Redirect, Response};
use validator::Validate;

use crate::domains::oauth2::models::AuthorizeQuery;
use crate::domains::oauth2::repos::OAuth2ClientRepo;
use crate::domains::sso::models::{AuthorizeParams, SsoSession};
use crate::domains::sso::routes::login::set_session_cookie;
use crate::domains::sso::session::{self, get_session_id};
use crate::shared::constants::oauth2 as oauth2_constants;
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

    let client = OAuth2ClientRepo::find_by_client_id(&state.db, &query.client_id)
        .await?
        .ok_or(AppError::BadRequest("invalid client_id".into()))?;

    if !client.enabled {
        return Err(AppError::BadRequest("client is disabled".into()));
    }
    if !client.allows_grant_type(oauth2_constants::GRANT_TYPE_AUTH_CODE) {
        return Err(AppError::BadRequest(format!(
            "grant_type '{}' not allowed",
            oauth2_constants::GRANT_TYPE_AUTH_CODE
        )));
    }

    if !client.redirect_uris.contains(&query.redirect_uri) {
        return Err(AppError::BadRequest("invalid redirect_uri".into()));
    }

    let requested_scopes: Vec<String> = query
        .scope
        .as_deref()
        .map(|s| s.split_whitespace().map(String::from).collect())
        .unwrap_or_default();

    for scope in &requested_scopes {
        if !client.scopes.contains(scope) {
            return Err(AppError::BadRequest(format!(
                "scope '{}' not allowed",
                scope
            )));
        }
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
                session::update(&state.cache, &sid, &existing).await?;
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

    let session_id = session::create(&state.cache, &sso).await?;

    let mut response = Redirect::to("/sso/login").into_response();
    response
        .headers_mut()
        .append(header::SET_COOKIE, set_session_cookie(&session_id));
    Ok(response)
}
