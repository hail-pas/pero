use askama::Template;
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;

use crate::api::extractors::ValidatedForm;
use crate::domain::identity::authn::AuthService;
use crate::domain::sso::models::LoginForm;
use crate::handler::social::{ProviderView, load_provider_views};
use crate::handler::sso::common::{
    load_sso_session, mark_sso_authenticated, render_tpl, set_account_cookie,
};
use crate::shared::error::AppError;
use crate::shared::state::AppState;

pub fn query_from_session(s: &crate::domain::sso::models::SsoSession) -> String {
    let p = &s.authorize_params;
    let mut q = format!(
        "client_id={}&redirect_uri={}&response_type=code&code_challenge={}&code_challenge_method={}",
        urlencoding::encode(&p.client_id),
        urlencoding::encode(&p.redirect_uri),
        urlencoding::encode(&p.code_challenge),
        urlencoding::encode(&p.code_challenge_method),
    );
    if let Some(scope) = &p.scope {
        q.push_str(&format!("&scope={}", urlencoding::encode(scope)));
    }
    if let Some(state) = &p.state {
        q.push_str(&format!("&state={}", urlencoding::encode(state)));
    }
    if let Some(nonce) = &p.nonce {
        q.push_str(&format!("&nonce={}", urlencoding::encode(nonce)));
    }
    q
}

#[derive(Template, Debug)]
#[template(path = "sso/login.html")]
pub struct LoginTemplate {
    pub providers: Vec<ProviderView>,
    pub error: String,
}

#[derive(Debug, Deserialize)]
pub struct LoginQuery {
    pub error: Option<String>,
}

pub async fn login_get(
    State(state): State<AppState>,
    Query(query): Query<LoginQuery>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let session = load_sso_session(&state, &headers).await;

    match (session, query.error) {
        (Ok((_sid, sso)), error) => {
            if sso.authenticated && sso.user_id.is_some() {
                return Ok(Redirect::to("/sso/consent").into_response());
            }
            let providers = load_provider_views(&state).await;
            let tpl = LoginTemplate {
                providers,
                error: error.unwrap_or_default(),
            };
            Ok(render_tpl(&tpl)?.into_response())
        }
        (Err(_redirect), Some(_error)) => {
            let providers = load_provider_views(&state).await;
            let tpl = LoginTemplate {
                providers,
                error: "session_expired".into(),
            };
            Ok(render_tpl(&tpl)?.into_response())
        }
        (Err(_redirect), None) => {
            let providers = load_provider_views(&state).await;
            let tpl = LoginTemplate {
                providers,
                error: "session_expired".into(),
            };
            Ok(render_tpl(&tpl)?.into_response())
        }
    }
}

pub async fn login_post(
    State(state): State<AppState>,
    headers: HeaderMap,
    ValidatedForm(form): ValidatedForm<LoginForm>,
) -> Result<Response, AppError> {
    let (sid, mut sso) = match load_sso_session(&state, &headers).await {
        Ok(value) => value,
        Err(_) => {
            let providers = load_provider_views(&state).await;
            let tpl = LoginTemplate {
                providers,
                error: "session_expired".into(),
            };
            return Ok(render_tpl(&tpl)?.into_response());
        }
    };

    let user = match AuthService::authenticate_with_password(
        &state,
        &form.identifier_type,
        &form.identifier,
        &form.password,
    )
    .await
    {
        Ok(user) => user,
        Err(AppError::Unauthorized) => {
            let providers = load_provider_views(&state).await;
            let tpl = LoginTemplate {
                providers,
                error: "invalid_credentials".into(),
            };
            return Ok(render_tpl(&tpl)?.into_response());
        }
        Err(err) => return Err(err),
    };

    mark_sso_authenticated(&state, &sid, &mut sso, user.id).await?;

    let mut response = Redirect::to("/sso/consent").into_response();
    response.headers_mut().append(
        axum::http::header::SET_COOKIE,
        set_account_cookie(&state, user.id, &headers).await?,
    );
    Ok(response)
}
