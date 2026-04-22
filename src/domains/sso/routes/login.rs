use askama::Template;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{Html, IntoResponse, Redirect, Response};

use crate::domains::identity::auth_service::AuthService;
use crate::domains::sso::models::LoginForm;
use crate::domains::sso::session::{self, COOKIE_NAME, get_session_id};
use crate::shared::error::AppError;
use crate::shared::extractors::ValidatedForm;
use crate::shared::state::AppState;

pub fn query_from_session(s: &crate::domains::sso::models::SsoSession) -> String {
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

pub fn set_session_cookie(session_id: &str) -> axum::http::HeaderValue {
    format!(
        "{}={}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=600",
        COOKIE_NAME, session_id
    )
    .parse()
    .unwrap()
}

#[derive(Template, Debug)]
#[template(path = "sso/login.html")]
pub struct LoginTemplate {
    pub client_name: Option<String>,
    pub identifier: String,
    pub identifier_type: String,
    pub error: Option<String>,
    pub query_params: String,
}

fn render_tpl(tpl: &LoginTemplate) -> Result<Html<String>, AppError> {
    tpl.render()
        .map(Html)
        .map_err(|e| AppError::Internal(e.to_string()))
}

pub async fn login_get(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let sid = get_session_id(&headers);
    match sid {
        Some(sid) => {
            let sso = session::get(&state.cache, &sid).await?;
            match sso {
                Some(s) => {
                    if s.authenticated && s.user_id.is_some() {
                        return Ok(Redirect::to("/sso/consent").into_response());
                    }
                    let qp = query_from_session(&s);
                    let tpl = LoginTemplate {
                        client_name: None,
                        identifier: String::new(),
                        identifier_type: "username".into(),
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

fn error_tpl(
    identifier: String,
    identifier_type: String,
    error: &str,
    qp: String,
) -> LoginTemplate {
    LoginTemplate {
        client_name: None,
        identifier,
        identifier_type,
        error: Some(error.into()),
        query_params: qp,
    }
}

pub async fn login_post(
    State(state): State<AppState>,
    headers: HeaderMap,
    ValidatedForm(form): ValidatedForm<LoginForm>,
) -> Result<Response, AppError> {
    let (sid, mut sso) = session::require(&state.cache, &headers).await?;

    let identifier = form.identifier.clone();
    let identifier_type = serde_json::to_string(&form.identifier_type)
        .unwrap_or_default()
        .trim_matches('"')
        .to_string();
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
            let qp = query_from_session(&sso);
            return Ok(render_tpl(&error_tpl(
                identifier,
                identifier_type,
                "invalid credentials",
                qp,
            ))?
            .into_response());
        }
        Err(AppError::Forbidden(_)) => {
            let qp = query_from_session(&sso);
            return Ok(render_tpl(&error_tpl(
                identifier,
                identifier_type,
                "account is disabled",
                qp,
            ))?
            .into_response());
        }
        Err(err) => return Err(err),
    };

    sso.user_id = Some(user.id);
    sso.authenticated = true;
    sso.auth_time = Some(chrono::Utc::now().timestamp());
    session::update(&state.cache, &sid, &sso).await?;

    Ok(Redirect::to("/sso/consent").into_response())
}
