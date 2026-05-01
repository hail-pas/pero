use askama::Template;
use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;

use crate::api::extractors::ValidatedForm;
use crate::domain::identity::authn::AuthService;
use crate::domain::social::store::SocialProviderRepo;
use crate::domain::sso::models::LoginForm;
use crate::handler::sso::common::{load_sso_session, mark_sso_authenticated, render_tpl};
use crate::shared::error::AppError;
use crate::shared::state::AppState;

#[derive(Debug, Clone)]
pub struct ProviderView {
    pub key: String,
    pub icon: String,
    pub name: String,
}

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

async fn load_social_providers(state: &AppState) -> Vec<ProviderView> {
    match SocialProviderRepo::list_enabled(&state.db).await {
        Ok(providers) => providers
            .iter()
            .map(|p| ProviderView {
                key: p.name.clone(),
                icon: provider_icon(&p.name),
                name: p.display_name.clone(),
            })
            .collect(),
        Err(_) => Vec::new(),
    }
}

fn provider_icon(name: &str) -> String {
    match name {
        "google" => "G".into(),
        "github" => "GH".into(),
        "wechat" => "W".into(),
        "apple" => "A".into(),
        "microsoft" => "M".into(),
        "qq" => "Q".into(),
        _ => name.chars().take(2).collect(),
    }
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
            let providers = load_social_providers(&state).await;
            let tpl = LoginTemplate {
                providers,
                error: error.unwrap_or_default(),
            };
            Ok(render_tpl(&tpl)?.into_response())
        }
        (Err(_redirect), Some(_error)) => {
            let providers = load_social_providers(&state).await;
            let tpl = LoginTemplate {
                providers,
                error: "session_expired".into(),
            };
            Ok(render_tpl(&tpl)?.into_response())
        }
        (Err(redirect), None) => Ok(redirect),
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
            let providers = load_social_providers(&state).await;
            let tpl = LoginTemplate {
                providers,
                error: "invalid_credentials".into(),
            };
            return Ok(render_tpl(&tpl)?.into_response());
        }
        Err(err) => return Err(err),
    };

    mark_sso_authenticated(&state, &sid, &mut sso, user.id).await?;

    Ok(Redirect::to("/sso/consent").into_response())
}
