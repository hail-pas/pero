use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;

use crate::domain::oauth2::store::OAuth2ClientRepo;
use crate::domain::session::SessionBinding;
use crate::shared::constants::cookies::ACCOUNT_TOKEN;
use crate::shared::error::AppError;
use crate::shared::state::AppState;

#[derive(Debug, Deserialize)]
pub struct EndSessionQuery {
    pub id_token_hint: Option<String>,
    pub post_logout_redirect_uri: Option<String>,
    pub state: Option<String>,
}

#[derive(askama::Template, Debug)]
#[template(path = "oidc/end_session.html")]
pub struct EndSessionTemplate;

pub async fn end_session(
    State(state): State<AppState>,
    Query(query): Query<EndSessionQuery>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let mut redirect_uri: Option<String> = None;
    let cookie_sid = extract_cookie_sid(&state, &headers);

    if let Some(ref id_token_str) = query.id_token_hint {
        let id_claims = match crate::infra::jwt::verify_id_token(id_token_str, &state.jwt_keys) {
            Ok(c) => c,
            Err(_) => {
                return end_session_cleanup(&state, &query, None, cookie_sid).await;
            }
        };

        if let Some(ref uri) = query.post_logout_redirect_uri {
            let client = match OAuth2ClientRepo::find_by_client_id(&state.db, &id_claims.aud)
                .await?
            {
                Some(c) => c,
                None => {
                    return end_session_cleanup(&state, &query, None, cookie_sid).await;
                }
            };

            if let Ok(verified) = crate::infra::jwt::verify_id_token_for_client(
                id_token_str,
                &state.jwt_keys,
                &client.client_id,
            ) {
                if client
                    .post_logout_redirect_uris
                    .iter()
                    .any(|u| u == uri)
                {
                    redirect_uri = Some(uri.clone());
                    let target_sid = verified.sid.as_deref().or(cookie_sid.as_deref());
                    if let Ok(user_id) = verified.sub.parse::<uuid::Uuid>() {
                        let binding = target_sid
                            .map(|sid| SessionBinding::from_sid(user_id, sid))
                            .unwrap_or_else(|| SessionBinding::user_only(user_id));
                        revoke_session_binding(&state, &binding).await;
                    }
                }
            }
        } else {
            let target_sid = id_claims.sid.as_deref().or(cookie_sid.as_deref());
            if let Ok(user_id) = id_claims.sub.parse::<uuid::Uuid>() {
                let binding = target_sid
                    .map(|sid| SessionBinding::from_sid(user_id, sid))
                    .unwrap_or_else(|| SessionBinding::user_only(user_id));
                revoke_session_binding(&state, &binding).await;
            }
        }
    } else {
        if let Some(token) = crate::shared::utils::extract_cookie(&headers, ACCOUNT_TOKEN) {
            if let Ok(claims) = crate::infra::jwt::verify_token(&token, &state.jwt_keys) {
                if let Ok(user_id) = claims.sub.parse::<uuid::Uuid>() {
                    let binding = claims
                        .sid
                        .as_deref()
                        .map(|sid| SessionBinding::from_sid(user_id, sid))
                        .unwrap_or_else(|| SessionBinding::user_only(user_id));
                    revoke_session_binding(&state, &binding).await;
                }
            }
        }
    }

    end_session_cleanup(&state, &query, redirect_uri, cookie_sid).await
}

async fn revoke_session_binding(state: &AppState, binding: &SessionBinding) {
    if let Err(e) = binding.revoke_all(&state.cache, &state.db).await {
        tracing::warn!(error = %e, "failed to revoke session binding during end_session");
    }
}

fn extract_cookie_sid(_state: &AppState, headers: &HeaderMap) -> Option<String> {
    let token = crate::shared::utils::extract_cookie(headers, ACCOUNT_TOKEN)?;
    let claims = crate::infra::jwt::decode_token_claims_unverified(&token).ok()?;
    claims.sid
}

async fn end_session_cleanup(
    state: &AppState,
    query: &EndSessionQuery,
    redirect_uri: Option<String>,
    _cookie_sid: Option<String>,
) -> Result<Response, AppError> {
    let clear_cookie =
        crate::handler::sso::common::build_cookie(ACCOUNT_TOKEN, "", &state.config.sso, 0)?;

    if let Some(uri) = redirect_uri {
        let mut params: Vec<(&str, &str)> = vec![];
        if let Some(ref s) = query.state {
            params.push(("state", s.as_str()));
        }
        let url = if params.is_empty() {
            uri.clone()
        } else {
            crate::shared::utils::append_query_params(&uri, &params)?
        };
        let mut response = Redirect::to(&url).into_response();
        response
            .headers_mut()
            .append(axum::http::header::SET_COOKIE, clear_cookie);
        return Ok(response);
    }

    let mut response = crate::shared::utils::render_tpl(&EndSessionTemplate)?.into_response();
    response
        .headers_mut()
        .append(axum::http::header::SET_COOKIE, clear_cookie);
    Ok(response)
}
