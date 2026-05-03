use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Redirect, Response};

use crate::domain::social::error::provider_not_found;
use crate::domain::social::service;
use crate::handler::social::social_callback_url;
use crate::handler::sso::common::load_sso_session;
use crate::shared::error::AppError;
use crate::shared::kv::KvStoreExt;
use crate::shared::state::AppState;

pub async fn social_login(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(provider): Path<String>,
) -> Result<Response, AppError> {
    let (sid, _sso) = match load_sso_session(&state, &headers).await {
        Ok(value) => value,
        Err(response) => return Ok(response),
    };

    let redirect_uri = social_callback_url(&state.config.oidc.issuer, &provider);

    let (url, _state_token) =
        service::build_authorize_url(&*state.repos.social, &*state.repos.kv, &provider, &sid, &redirect_uri).await?;

    Ok(Redirect::to(&url).into_response())
}

pub async fn social_bind(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(provider): Path<String>,
) -> Result<Response, AppError> {
    let user_id =
        crate::handler::account::common::get_account_user_id(&state, &headers).await?;

    let existing = state.repos.identities.find_by_user_and_provider(
        user_id, &provider,
    )
    .await?;
    if existing.is_some() {
        return Err(crate::domain::identity::error::provider_already_bound(
            &provider,
        ));
    }

    let _provider = state.repos.social.find_enabled_provider_by_name(
        &provider,
    )
    .await?
    .ok_or(provider_not_found())?;

    let redirect_uri = format!(
        "{}/sso/social/{}/bind-callback",
        state.config.oidc.issuer.trim_end_matches('/'),
        provider,
    );

    let state_token = uuid::Uuid::new_v4().to_string();
    let social_state = service::SocialBindState {
        provider: provider.clone(),
        bind_user_id: user_id.to_string(),
    };
    state.repos.kv.set_json(
        &crate::shared::cache_keys::social::state_key(&state_token),
        &social_state,
        600,
    )
    .await?;

    let provider =
        state.repos.social.find_provider_by_name(&provider)
            .await?
            .ok_or(provider_not_found())?;

    let url = crate::shared::utils::append_query_params(
        &provider.authorize_url,
        &[
            ("client_id", &provider.client_id),
            ("response_type", "code"),
            ("state", &state_token),
            ("redirect_uri", &redirect_uri),
        ],
    )?;

    Ok(Redirect::to(&url).into_response())
}
