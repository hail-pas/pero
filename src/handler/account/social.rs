use askama::Template;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

use crate::domain::identity::service;
use crate::domain::identity::store::IdentityRepo;
use crate::domain::social::store::SocialProviderRepo;
use crate::handler::account::common;
use crate::handler::account::common::{SocialProviderView, user_display_name, user_initial};
use crate::shared::error::AppError;
use crate::shared::state::AppState;

#[derive(Template, Debug)]
#[template(path = "account/social_accounts.html")]
pub struct SocialAccountsTemplate {
    pub active: String,
    pub user_initial: String,
    pub user_name: String,
    pub providers: Vec<SocialProviderView>,
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

async fn build_providers(
    state: &AppState,
    user_id: uuid::Uuid,
) -> Result<Vec<SocialProviderView>, AppError> {
    let identities = IdentityRepo::list_by_user(&state.db, user_id).await?;
    let all_providers = SocialProviderRepo::list_enabled(&state.db).await?;
    let bound: Vec<String> = identities.iter().map(|i| i.provider.clone()).collect();

    let mut views = Vec::new();

    for identity in &identities {
        if identity.provider == "password" {
            continue;
        }
        views.push(SocialProviderView {
            key: identity.provider.clone(),
            icon: provider_icon(&identity.provider),
            name: identity.provider.clone(),
            display_name: identity.provider.clone(),
            created_at: identity.created_at.format("%Y-%m-%d").to_string(),
            bound: true,
            unbound: false,
        });
    }

    for p in &all_providers {
        if bound.contains(&p.name) {
            continue;
        }
        views.push(SocialProviderView {
            key: p.name.clone(),
            icon: provider_icon(&p.name),
            name: p.name.clone(),
            display_name: p.display_name.clone(),
            created_at: String::new(),
            bound: false,
            unbound: true,
        });
    }

    Ok(views)
}

pub async fn social_get(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let user = common::get_account_user(&state, &headers).await?;
    let providers = build_providers(&state, user.id).await?;
    let tpl = SocialAccountsTemplate {
        active: "social_accounts".into(),
        user_initial: user_initial(&user),
        user_name: user_display_name(&user),
        providers,
    };
    Ok(common::render_tpl(&tpl)?.into_response())
}

#[derive(Debug, Deserialize)]
pub struct UnbindForm {
    pub provider: String,
}

pub async fn unbind_post(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Form(form): axum::Form<UnbindForm>,
) -> Result<Response, AppError> {
    let user_id = common::get_account_user_id(&state, &headers).await?;
    match service::unbind_identity(&state, user_id, &form.provider).await {
        Ok(_) => Ok(axum::Json(crate::api::response::MessageResponse::success(
            "Social account unlinked.",
        ))
        .into_response()),
        Err(err) => Err(err),
    }
}
