use axum::extract::{Query, State};
use axum::response::{IntoResponse, Redirect, Response};

use crate::domains::oauth2::models::AuthorizeQuery;
use crate::domains::oauth2::repos::{AuthCodeRepo, OAuth2ClientRepo};
use crate::shared::error::AppError;
use crate::shared::extractors::AuthUser;
use crate::shared::state::AppState;

pub async fn authorize(
    State(state): State<AppState>,
    auth_user: AuthUser,
    Query(query): Query<AuthorizeQuery>,
) -> Result<Response, AppError> {
    if query.response_type != "code" {
        return Err(AppError::BadRequest("unsupported response_type".into()));
    }

    let client = OAuth2ClientRepo::find_by_client_id(&state.db, &query.client_id)
        .await?
        .ok_or(AppError::BadRequest("invalid client_id".into()))?;

    if !client.enabled {
        return Err(AppError::BadRequest("client is disabled".into()));
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

    let scopes = if requested_scopes.is_empty() {
        client.scopes.clone()
    } else {
        requested_scopes
    };

    let method = query
        .code_challenge_method
        .as_deref()
        .unwrap_or("S256");
    if method != "S256" && method != "plain" {
        return Err(AppError::BadRequest("invalid code_challenge_method".into()));
    }

    let code = uuid::Uuid::new_v4().to_string().replace('-', "");

    AuthCodeRepo::create(
        &state.db,
        &code,
        client.id,
        auth_user.user_id,
        &query.redirect_uri,
        &scopes,
        Some(&query.code_challenge),
        Some(method),
        state.config.oauth2.auth_code_ttl_minutes,
    )
    .await?;

    let mut redirect_url = format!("{}?code={}", query.redirect_uri, code);
    if let Some(state_param) = &query.state {
        redirect_url.push_str(&format!("&state={}", state_param));
    }

    Ok(Redirect::temporary(&redirect_url).into_response())
}
