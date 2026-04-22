use askama::Template;
use axum::Form;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{Html, IntoResponse, Redirect, Response};

use crate::domains::sso::models::ConsentAction;
use crate::domains::sso::routes::login::query_from_session;
use crate::domains::sso::service;
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

                    let consent = service::build_consent_view(&state, &sso).await?;
                    let qp = query_from_session(&sso);
                    let tpl = ConsentTemplate {
                        client_name: consent.client_name,
                        scopes: consent.scopes,
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

    let redirect = service::handle_consent_action(&state, &sid, &sso, action.action).await?;
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
