use askama::Template;
use axum::Form;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{Html, IntoResponse, Redirect, Response};

use crate::domains::oauth2::repos::{AuthCodeRepo, OAuth2ClientRepo};
use crate::domains::sso::models::{ConsentAction, ConsentDecision};
use crate::domains::sso::routes::login::query_from_session;
use crate::domains::sso::session::{self, get_session_id};
use crate::shared::error::AppError;
use crate::shared::state::AppState;

#[derive(Template, Debug)]
#[template(path = "sso/consent.html")]
pub struct ConsentTemplate {
    pub client_name: String,
    pub scopes: Vec<String>,
    pub error: Option<String>,
    pub query_params: String,
}

fn render_tpl(tpl: &ConsentTemplate) -> Result<Html<String>, AppError> {
    tpl.render()
        .map(Html)
        .map_err(|e| AppError::Internal(e.to_string()))
}

pub async fn consent_get(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let sid = get_session_id(&headers);
    match sid {
        Some(sid) => {
            let sso = session::get(&state.cache, &sid).await?;
            match sso {
                Some(sso) => {
                    if !sso.authenticated || sso.user_id.is_none() {
                        return Ok(Redirect::to("/sso/login").into_response());
                    }

                    let client = OAuth2ClientRepo::find_by_client_id(
                        &state.db,
                        &sso.authorize_params.client_id,
                    )
                    .await?
                    .ok_or(AppError::BadRequest("invalid client_id".into()))?;

                    let scopes: Vec<String> = sso
                        .authorize_params
                        .scope
                        .as_deref()
                        .map(|s| s.split_whitespace().map(String::from).collect())
                        .unwrap_or_default();

                    let qp = query_from_session(&sso);
                    let tpl = ConsentTemplate {
                        client_name: client.client_name,
                        scopes,
                        error: None,
                        query_params: qp,
                    };
                    Ok(render_tpl(&tpl)?.into_response())
                }
                None => Ok(Redirect::to("/oauth2/authorize").into_response()),
            }
        }
        None => Ok(Redirect::to("/oauth2/authorize").into_response()),
    }
}

pub async fn consent_post(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(action): Form<ConsentAction>,
) -> Result<Response, AppError> {
    let (sid, sso) = session::require(&state.cache, &headers).await?;

    if !sso.authenticated || sso.user_id.is_none() {
        return Ok(Redirect::to("/sso/login").into_response());
    }

    let user_id = sso.user_id.unwrap();
    let p = &sso.authorize_params;

    if action.action == ConsentDecision::Deny {
        session::delete(&state.cache, &sid).await?;
        let mut redirect = format!("{}?error=access_denied", p.redirect_uri);
        if let Some(s) = &p.state {
            redirect.push_str(&format!("&state={}", urlencoding::encode(s)));
        }
        return Ok(Redirect::to(&redirect).into_response());
    }

    let client = OAuth2ClientRepo::find_by_client_id(&state.db, &p.client_id)
        .await?
        .ok_or(AppError::BadRequest("invalid client_id".into()))?;

    let scopes: Vec<String> = p
        .scope
        .as_deref()
        .map(|s| s.split_whitespace().map(String::from).collect())
        .unwrap_or_else(|| client.scopes.clone());

    let code = uuid::Uuid::new_v4().to_string().replace('-', "");

    AuthCodeRepo::create(
        &state.db,
        &code,
        client.id,
        user_id,
        &p.redirect_uri,
        &scopes,
        Some(&p.code_challenge),
        Some(&p.code_challenge_method),
        p.nonce.as_deref(),
        sso.auth_time
            .unwrap_or_else(|| chrono::Utc::now().timestamp()),
        state.config.oauth2.auth_code_ttl_minutes,
    )
    .await?;

    session::delete(&state.cache, &sid).await?;

    let mut redirect = format!("{}?code={}", p.redirect_uri, urlencoding::encode(&code));
    if let Some(s) = &p.state {
        redirect.push_str(&format!("&state={}", urlencoding::encode(s)));
    }

    let mut response = Redirect::to(&redirect).into_response();
    response.headers_mut().append(
        axum::http::header::SET_COOKIE,
        format!(
            "{}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0",
            session::COOKIE_NAME
        )
        .parse()
        .unwrap(),
    );
    Ok(response)
}
