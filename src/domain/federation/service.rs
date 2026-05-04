use crate::domain::credential::repo::IdentityStore;
use crate::domain::federation::entity::{
    CreateSocialProviderRequest, SocialProvider, SocialProviderPublic, SocialUserInfo,
    UpdateSocialProviderRequest,
};
use crate::domain::federation::error::{
    provider_disabled, provider_not_found, social_state_invalid,
};
use crate::domain::federation::repo::SocialStore;
use crate::domain::federation::userinfo;
use crate::domain::user::repo::UserStore;
use crate::shared::cache_keys::social::state_key;
use crate::shared::error::AppError;
use crate::shared::kv::{KvStore, KvStoreExt};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub async fn list_enabled_providers(
    social: &dyn SocialStore,
) -> Result<Vec<SocialProviderPublic>, AppError> {
    let providers = social.list_enabled_providers().await?;
    Ok(providers.iter().map(SocialProviderPublic::from).collect())
}

pub async fn create_provider(
    social: &dyn SocialStore,
    req: &CreateSocialProviderRequest,
) -> Result<SocialProvider, AppError> {
    social.create_provider(req).await
}

pub async fn list_providers(social: &dyn SocialStore) -> Result<Vec<SocialProvider>, AppError> {
    social.list_all_providers().await
}

pub async fn get_provider(social: &dyn SocialStore, id: Uuid) -> Result<SocialProvider, AppError> {
    social
        .find_provider_by_id(id)
        .await?
        .ok_or(provider_not_found())
}

pub async fn update_provider(
    social: &dyn SocialStore,
    id: Uuid,
    req: &UpdateSocialProviderRequest,
) -> Result<SocialProvider, AppError> {
    social.update_provider(id, req).await
}

pub async fn delete_provider(social: &dyn SocialStore, id: Uuid) -> Result<(), AppError> {
    social.delete_provider(id).await
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SocialState {
    pub sso_session_id: String,
    pub provider: String,
    pub account_login: Option<bool>,
    pub account_next: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SocialBindState {
    pub provider: String,
    pub bind_user_id: String,
}

pub async fn build_authorize_url(
    social: &dyn SocialStore,
    kv: &dyn KvStore,
    provider_name: &str,
    sso_session_id: &str,
    redirect_uri: &str,
) -> Result<(String, String), AppError> {
    let provider = social
        .find_enabled_provider_by_name(provider_name)
        .await?
        .ok_or(provider_not_found())?;

    let state_token = uuid::Uuid::new_v4().to_string();
    let social_state = SocialState {
        sso_session_id: sso_session_id.to_string(),
        provider: provider_name.to_string(),
        account_login: None,
        account_next: None,
    };
    kv.set_json(&state_key(&state_token), &social_state, 600)
        .await?;

    let mut params: Vec<(&str, String)> = vec![
        ("client_id", provider.client_id.clone()),
        ("response_type", "code".to_string()),
        ("state", state_token.clone()),
        ("redirect_uri", redirect_uri.to_string()),
    ];
    if !provider.scopes.is_empty() {
        params.push(("scope", provider.scopes.join(" ")));
    }

    let url = crate::shared::utils::append_query_params(
        &provider.authorize_url,
        &params
            .iter()
            .map(|(k, v)| (*k, v.as_str()))
            .collect::<Vec<_>>(),
    )?;

    Ok((url, state_token))
}

pub async fn build_account_login_url(
    social: &dyn SocialStore,
    kv: &dyn KvStore,
    provider_name: &str,
    redirect_uri: &str,
    next: Option<&str>,
) -> Result<(String, String), AppError> {
    let provider = social
        .find_enabled_provider_by_name(provider_name)
        .await?
        .ok_or(provider_not_found())?;

    let state_token = uuid::Uuid::new_v4().to_string();
    let social_state = SocialState {
        sso_session_id: String::new(),
        provider: provider_name.to_string(),
        account_login: Some(true),
        account_next: next.map(|s| s.to_string()),
    };
    kv.set_json(&state_key(&state_token), &social_state, 600)
        .await?;

    let mut params: Vec<(&str, String)> = vec![
        ("client_id", provider.client_id.clone()),
        ("response_type", "code".to_string()),
        ("state", state_token.clone()),
        ("redirect_uri", redirect_uri.to_string()),
    ];
    if !provider.scopes.is_empty() {
        params.push(("scope", provider.scopes.join(" ")));
    }

    let url = crate::shared::utils::append_query_params(
        &provider.authorize_url,
        &params
            .iter()
            .map(|(k, v)| (*k, v.as_str()))
            .collect::<Vec<_>>(),
    )?;

    Ok((url, state_token))
}

pub async fn handle_callback(
    social: &dyn SocialStore,
    kv: &dyn KvStore,
    http: &dyn crate::domain::federation::http::HttpClient,
    code: &str,
    state_token: &str,
    callback_provider: &str,
    redirect_uri: &str,
) -> Result<(SocialUserInfo, SocialState), AppError> {
    let key = state_key(state_token);
    let social_state: SocialState = kv.get_json(&key).await?.ok_or_else(social_state_invalid)?;

    kv.del(&key).await?;

    if social_state.provider != callback_provider {
        return Err(AppError::BadRequest(
            "provider path does not match state".into(),
        ));
    }

    let provider = social
        .find_provider_by_name(&social_state.provider)
        .await?
        .ok_or(provider_not_found())?;

    if !provider.enabled {
        return Err(provider_disabled());
    }

    let access_token = userinfo::exchange_code(http, &provider, code, redirect_uri).await?;
    let user_info = userinfo::fetch_userinfo(http, &provider, &access_token).await?;

    Ok((user_info, social_state))
}

pub async fn find_or_create_user(
    users: &dyn UserStore,
    identities: &dyn IdentityStore,
    info: &SocialUserInfo,
) -> Result<crate::domain::user::entity::User, AppError> {
    if let Some(identity) = identities
        .find_by_provider(&info.provider, &info.provider_uid)
        .await?
    {
        let user = users
            .find_by_id(identity.user_id)
            .await?
            .ok_or(AppError::Internal(
                "user for social identity not found".into(),
            ))?;
        if !user.is_active() {
            return Err(AppError::Unauthorized);
        }
        return Ok(user);
    }

    if info.is_trusted_provider() && info.email_verified {
        if let Some(ref email) = info.email {
            if let Some(user) = users.find_by_email(email).await? {
                if !user.is_active() {
                    return Err(AppError::Unauthorized);
                }
                users
                    .link_social_identity(user.id, &info.provider, &info.provider_uid)
                    .await?;
                if !user.email_verified {
                    users.set_email_verified_flag(user.id).await?;
                }
                return Ok(user);
            }
        }
    }

    let base_username = info
        .username
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| {
            let uid_prefix: String = info.provider_uid.chars().take(8).collect();
            format!("{}_{}", info.provider, uid_prefix)
        });

    let username = users.resolve_unique_username(&base_username).await?;

    let user = users
        .create_social_user(
            &username,
            info.email.as_deref(),
            info.display_name.as_deref(),
            &info.provider,
            &info.provider_uid,
            info.email_verified,
        )
        .await?;

    Ok(user)
}

pub async fn bind_social_identity(
    social: &dyn SocialStore,
    identities: &dyn IdentityStore,
    kv: &dyn KvStore,
    http: &dyn crate::domain::federation::http::HttpClient,
    oidc_issuer: &str,
    code: &str,
    state_token: &str,
    current_user_id: uuid::Uuid,
) -> Result<(), AppError> {
    let key = state_key(state_token);
    let social_state: SocialBindState =
        kv.get_json(&key).await?.ok_or_else(social_state_invalid)?;
    kv.del(&key).await?;

    let user_id: uuid::Uuid = social_state
        .bind_user_id
        .parse()
        .map_err(|_| AppError::Internal("invalid bind_user_id in state".into()))?;

    if user_id != current_user_id {
        return Err(AppError::Forbidden(
            "session does not match bind state".into(),
        ));
    }
    let provider = social
        .find_provider_by_name(&social_state.provider)
        .await?
        .ok_or(provider_not_found())?;
    if !provider.enabled {
        return Err(provider_disabled());
    }

    let redirect_uri = format!(
        "{}/sso/social/{}/bind-callback",
        oidc_issuer.trim_end_matches('/'),
        social_state.provider,
    );

    let access_token = userinfo::exchange_code(http, &provider, code, &redirect_uri).await?;
    let user_info = userinfo::fetch_userinfo(http, &provider, &access_token).await?;

    let existing = identities
        .find_by_provider(&user_info.provider, &user_info.provider_uid)
        .await?;
    if let Some(existing_identity) = existing {
        if existing_identity.user_id != user_id {
            return Err(AppError::Conflict(
                "this social account is already linked to another user".into(),
            ));
        }
        return Ok(());
    }

    identities
        .create_social(user_id, &user_info.provider, &user_info.provider_uid)
        .await?;
    Ok(())
}
