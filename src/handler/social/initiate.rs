use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Redirect, Response};

use crate::domain::social::error::provider_not_found;
use crate::domain::social::service;
use crate::handler::sso::common::load_sso_session;
use crate::shared::error::AppError;
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

    let redirect_uri = format!(
        "{}/sso/social/{}/callback",
        state.config.oidc.issuer.trim_end_matches('/'),
        provider
    );

    let (url, _state_token) =
        service::build_authorize_url(&state, &provider, &sid, &redirect_uri).await?;

    Ok(Redirect::to(&url).into_response())
}

pub async fn social_bind(
    State(state): State<AppState>,
    user_id: axum::extract::Extension<uuid::Uuid>,
    Path(provider): Path<String>,
) -> Result<Response, AppError> {
    let existing = crate::domain::identity::store::IdentityRepo::find_by_user_and_provider(
        &state.db, user_id.0, &provider,
    )
    .await?;
    if existing.is_some() {
        return Err(crate::domain::identity::error::provider_already_bound(
            &provider,
        ));
    }

    let _provider = crate::domain::social::store::SocialProviderRepo::find_enabled_by_name(
        &state.db, &provider,
    )
    .await?
    .ok_or(provider_not_found())?;

    let redirect_uri = format!(
        "{}/sso/social/{}/callback?bind_user={}",
        state.config.oidc.issuer.trim_end_matches('/'),
        provider,
        user_id.0
    );

    let state_token = uuid::Uuid::new_v4().to_string();
    let social_state = serde_json::json!({
        "provider": provider,
        "bind_user_id": user_id.0.to_string(),
    });
    crate::infra::cache::set_json(
        &state.cache,
        &format!("social_state:{state_token}"),
        &social_state,
        600,
    )
    .await?;

    let _provider =
        crate::domain::social::store::SocialProviderRepo::find_by_name(&state.db, &provider)
            .await?
            .ok_or(provider_not_found())?;

    let redirect_uri_encoded = urlencoding::encode(&redirect_uri);
    let url = format!(
        "{}?client_id={}&response_type=code&state={}&redirect_uri={}",
        _provider.authorize_url,
        urlencoding::encode(&_provider.client_id),
        urlencoding::encode(&state_token),
        redirect_uri_encoded,
    );

    Ok(Redirect::to(&url).into_response())
}
