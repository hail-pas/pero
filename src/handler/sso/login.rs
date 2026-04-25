use askama::Template;
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;

use crate::api::extractors::ValidatedForm;
use crate::domain::identity::authn::AuthService;
use crate::domain::social::entity::SocialProviderPublic;
use crate::domain::social::store::SocialProviderRepo;
use crate::domain::sso::models::LoginForm;
use crate::domain::sso::session;
use crate::handler::sso::common::{load_sso_session, render_tpl};
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
    pub client_name: Option<String>,
    pub identifier: String,
    pub identifier_type: String,
    pub error: Option<String>,
    pub query_params: String,
    pub social_providers: Vec<SocialProviderPublic>,
}

async fn load_social_providers(state: &AppState) -> Vec<SocialProviderPublic> {
    match SocialProviderRepo::list_enabled(&state.db).await {
        Ok(providers) => providers.iter().map(SocialProviderPublic::from).collect(),
        Err(_) => Vec::new(),
    }
}

#[derive(Debug, Deserialize)]
pub struct LoginQuery {
    pub error: Option<String>,
}

pub async fn login_get(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<LoginQuery>,
) -> Result<Response, AppError> {
    let session = load_sso_session(&state, &headers).await;

    match (session, query.error) {
        (Ok((_sid, sso)), _) => {
            if sso.authenticated && sso.user_id.is_some() {
                return Ok(Redirect::to("/sso/consent").into_response());
            }
            let social_providers = load_social_providers(&state).await;
            let tpl = LoginTemplate {
                client_name: None,
                identifier: String::new(),
                identifier_type: "username".into(),
                error: None,
                query_params: query_from_session(&sso),
                social_providers,
            };
            Ok(render_tpl(&tpl)?.into_response())
        }
        (Err(_), Some(error)) => {
            let social_providers = load_social_providers(&state).await;
            let tpl = LoginTemplate {
                client_name: None,
                identifier: String::new(),
                identifier_type: "username".into(),
                error: Some(error),
                query_params: String::new(),
                social_providers,
            };
            Ok(render_tpl(&tpl)?.into_response())
        }
        (Err(redirect), None) => Ok(redirect),
    }
}

fn error_tpl(
    identifier: String,
    identifier_type: String,
    error: &str,
    qp: String,
    social_providers: Vec<SocialProviderPublic>,
) -> LoginTemplate {
    LoginTemplate {
        client_name: None,
        identifier,
        identifier_type,
        error: Some(error.into()),
        query_params: qp,
        social_providers,
    }
}

pub async fn login_post(
    State(state): State<AppState>,
    headers: HeaderMap,
    ValidatedForm(form): ValidatedForm<LoginForm>,
) -> Result<Response, AppError> {
    let (sid, mut sso) = match load_sso_session(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return Ok(response),
    };

    let identifier = form.identifier.clone();
    let identifier_type = match form.identifier_type {
        crate::domain::identity::models::IdentifierType::Username => "username",
        crate::domain::identity::models::IdentifierType::Email => "email",
        crate::domain::identity::models::IdentifierType::Phone => "phone",
    }
    .to_string();
    let social_providers = load_social_providers(&state).await;
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
                social_providers,
            ))?
            .into_response());
        }
        Err(err) => return Err(err),
    };

    sso.user_id = Some(user.id);
    sso.authenticated = true;
    sso.auth_time = Some(chrono::Utc::now().timestamp());
    session::update(
        &state.cache,
        &sid,
        &sso,
        state.config.sso.session_ttl_seconds,
    )
    .await?;

    Ok(Redirect::to("/sso/consent").into_response())
}
