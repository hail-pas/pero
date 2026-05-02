use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;

use crate::domain::identity::session;
use crate::domain::oauth2::store::{OAuth2ClientRepo, RefreshTokenRepo};
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
    _headers: HeaderMap,
) -> Result<Response, AppError> {
    let mut redirect_uri: Option<String> = None;

    if let Some(ref id_token_str) = query.id_token_hint {
        let id_claims = crate::infra::jwt::verify_id_token(id_token_str, &state.jwt_keys)?;

        let user_id: uuid::Uuid = id_claims
            .sub
            .parse()
            .map_err(|_| AppError::BadRequest("invalid id_token_hint sub".into()))?;

        if let Some(ref uri) = query.post_logout_redirect_uri {
            let client = OAuth2ClientRepo::find_by_client_id(&state.db, &id_claims.aud)
                .await?
                .ok_or(AppError::BadRequest("unknown client".into()))?;

            if !client.post_logout_redirect_uris.iter().any(|u| u == uri) {
                return Err(AppError::BadRequest(
                    "post_logout_redirect_uri not registered".into(),
                ));
            }

            redirect_uri = Some(uri.clone());
        }

        if let Some(ref sid) = id_claims.sid {
            let _ = session::revoke_session(&state.cache, sid).await;
        } else {
            let _ = session::revoke_user_sessions(&state.cache, user_id).await;
        }

        if let Err(e) = RefreshTokenRepo::revoke_all_for_user(&state.db, user_id).await {
            tracing::warn!(error = %e, "failed to revoke oauth2 tokens during end_session");
        }
    }

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
