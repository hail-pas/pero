use askama::Template;
use axum::extract::{Form, Path, Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Redirect, Response};
use serde::{Deserialize, Serialize};

use crate::domain::auth::service::AuthService;
use crate::domain::user::models::IdentifierType;
use crate::handler::account::common::{extract_cookie, render_tpl};
use crate::handler::social::{ProviderView, load_provider_views, social_callback_url};
use crate::shared::error::AppError;
use crate::shared::state::AppState;
use crate::shared::utils::safe_local_path;

#[derive(Debug, Deserialize)]
pub struct LoginQuery {
    pub next: Option<String>,
}

#[derive(Debug, Template)]
#[template(path = "account/login.html")]
pub struct LoginTemplate {
    pub error: String,
    pub providers: Vec<ProviderView>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct LoginForm {
    pub identifier_type: String,
    pub identifier: String,
    pub password: String,
}

pub async fn login_get(
    State(state): State<AppState>,
    Query(query): Query<LoginQuery>,
) -> Result<Response, AppError> {
    let providers = load_provider_views(&state).await;
    let tpl = LoginTemplate {
        error: String::new(),
        providers,
    };
    let mut response = render_tpl(&tpl)?.into_response();
    if let Some(next) = query.next {
        let cookie = format!(
            "pero_login_next={}; Path=/; HttpOnly; SameSite=Lax; Max-Age=300",
            urlencoding::encode(&next)
        );
        response.headers_mut().append(
            axum::http::header::SET_COOKIE,
            axum::http::HeaderValue::from_str(&cookie)
                .map_err(|e| AppError::Internal(format!("invalid cookie: {e}")))?,
        );
    }
    Ok(response)
}

pub async fn login_post(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Result<Response, AppError> {
    let providers = load_provider_views(&state).await;
    let id_type = match form.identifier_type.as_str() {
        "email" => IdentifierType::Email,
        "phone" => IdentifierType::Phone,
        _ => IdentifierType::Username,
    };

    let user = match AuthService::authenticate_with_password(
        &*state.repos.users,
        &*state.repos.identities,
        &id_type,
        &form.identifier,
        &form.password,
    )
    .await
    {
        Ok(user) => user,
        Err(AppError::Unauthorized) => {
            let tpl = LoginTemplate {
                error: "invalid_credentials".into(),
                providers,
            };
            return Ok(render_tpl(&tpl)?.into_response());
        }
        Err(err) => return Err(err),
    };

    let cookie = crate::handler::sso::common::set_account_cookie(&state, user.id, &headers).await?;

    let next = extract_cookie(&headers, "pero_login_next")
        .and_then(|s| safe_local_path(&s))
        .unwrap_or_else(|| "/account/profile".to_string());

    let mut response = Redirect::to(&next).into_response();
    response
        .headers_mut()
        .append(axum::http::header::SET_COOKIE, cookie);
    let clear = axum::http::HeaderValue::from_str(
        "pero_login_next=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0",
    )
    .map_err(|e| AppError::Internal(format!("invalid cookie: {e}")))?;
    response
        .headers_mut()
        .append(axum::http::header::SET_COOKIE, clear);
    Ok(response)
}

pub async fn account_social_login(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(provider): Path<String>,
) -> Result<Response, AppError> {
    let redirect_uri = social_callback_url(&state.config.oidc.issuer, &provider);
    let next = extract_cookie(&headers, "pero_login_next").filter(|s| s.starts_with('/'));
    let (url, _) = crate::domain::federation::service::build_account_login_url(
        &*state.repos.social,
        &*state.repos.kv,
        &provider,
        &redirect_uri,
        next.as_deref().and_then(safe_local_path).as_deref(),
    )
    .await?;
    Ok(Redirect::to(&url).into_response())
}
