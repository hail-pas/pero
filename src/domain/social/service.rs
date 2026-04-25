use crate::domain::identity::store::{IdentityRepo, UserRepo};
use crate::domain::social::entity::{
    CreateSocialProviderRequest, SocialProvider, SocialProviderPublic, SocialUserInfo,
    UpdateSocialProviderRequest,
};
use crate::domain::social::error::{provider_disabled, provider_not_found, social_state_invalid};
use crate::domain::social::store::SocialProviderRepo;
use crate::domain::social::userinfo;
use crate::infra::cache;
use crate::shared::error::AppError;
use crate::shared::state::AppState;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub async fn list_enabled_providers(
    state: &AppState,
) -> Result<Vec<SocialProviderPublic>, AppError> {
    let providers = SocialProviderRepo::list_enabled(&state.db).await?;
    Ok(providers.iter().map(SocialProviderPublic::from).collect())
}

pub async fn create_provider(
    state: &AppState,
    req: &CreateSocialProviderRequest,
) -> Result<SocialProvider, AppError> {
    SocialProviderRepo::create(&state.db, req).await
}

pub async fn list_providers(state: &AppState) -> Result<Vec<SocialProvider>, AppError> {
    SocialProviderRepo::list_all(&state.db).await
}

pub async fn get_provider(state: &AppState, id: Uuid) -> Result<SocialProvider, AppError> {
    SocialProviderRepo::find_by_id(&state.db, id)
        .await?
        .ok_or(provider_not_found())
}

pub async fn update_provider(
    state: &AppState,
    id: Uuid,
    req: &UpdateSocialProviderRequest,
) -> Result<SocialProvider, AppError> {
    SocialProviderRepo::update(&state.db, id, req).await
}

pub async fn delete_provider(state: &AppState, id: Uuid) -> Result<(), AppError> {
    SocialProviderRepo::delete(&state.db, id).await
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SocialState {
    pub sso_session_id: String,
    pub provider: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct SocialBindState {
    provider: String,
    bind_user_id: String,
}

pub async fn build_authorize_url(
    state: &AppState,
    provider_name: &str,
    sso_session_id: &str,
    redirect_uri: &str,
) -> Result<(String, String), AppError> {
    let provider = SocialProviderRepo::find_enabled_by_name(&state.db, provider_name)
        .await?
        .ok_or(provider_not_found())?;

    let state_token = uuid::Uuid::new_v4().to_string();
    let social_state = SocialState {
        sso_session_id: sso_session_id.to_string(),
        provider: provider_name.to_string(),
    };
    cache::set_json(
        &state.cache,
        &format!("social_state:{state_token}"),
        &social_state,
        600,
    )
    .await?;

    let scopes = if provider.scopes.is_empty() {
        String::new()
    } else {
        urlencoding::encode(&provider.scopes.join(" ")).into()
    };

    let mut url = format!(
        "{}?client_id={}&response_type=code&state={}&redirect_uri={}",
        provider.authorize_url,
        urlencoding::encode(&provider.client_id),
        urlencoding::encode(&state_token),
        urlencoding::encode(redirect_uri),
    );
    if !scopes.is_empty() {
        url.push_str(&format!("&scope={scopes}"));
    }

    Ok((url, state_token))
}

pub async fn handle_callback(
    state: &AppState,
    code: &str,
    state_token: &str,
    redirect_uri: &str,
) -> Result<(SocialUserInfo, SocialState), AppError> {
    let key = format!("social_state:{state_token}");
    let social_state: SocialState = cache::get_json(&state.cache, &key)
        .await?
        .ok_or_else(social_state_invalid)?;

    cache::del(&state.cache, &key).await?;

    let provider = SocialProviderRepo::find_by_name(&state.db, &social_state.provider)
        .await?
        .ok_or(provider_not_found())?;

    if !provider.enabled {
        return Err(provider_disabled());
    }

    let access_token = userinfo::exchange_code(&provider, code, redirect_uri).await?;
    let user_info = userinfo::fetch_userinfo(&provider, &access_token).await?;

    Ok((user_info, social_state))
}

pub async fn find_or_create_user(
    state: &AppState,
    info: &SocialUserInfo,
) -> Result<crate::domain::identity::entity::User, AppError> {
    if let Some(identity) =
        IdentityRepo::find_by_provider(&state.db, &info.provider, &info.provider_uid).await?
    {
        let user = UserRepo::find_by_id(&state.db, identity.user_id)
            .await?
            .ok_or(AppError::Internal(
                "user for social identity not found".into(),
            ))?;
        if !user.is_active() {
            return Err(AppError::Unauthorized);
        }
        return Ok(user);
    }

    if let Some(ref email) = info.email {
        if let Some(user) = UserRepo::find_by_email(&state.db, email).await? {
            if !user.is_active() {
                return Err(AppError::Unauthorized);
            }
            sqlx::query(
                "INSERT INTO identities (user_id, provider, provider_uid, verified) VALUES ($1, $2, $3, true)",
            )
            .bind(user.id)
            .bind(&info.provider)
            .bind(&info.provider_uid)
            .execute(&state.db)
            .await?;
            return Ok(user);
        }
    }

    let mut tx = state.db.begin().await?;

    let base_username = info
        .username
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| {
            let uid_prefix: String = info.provider_uid.chars().take(8).collect();
            format!("{}_{}", info.provider, uid_prefix)
        });
    let base_email = info
        .email
        .clone()
        .unwrap_or_else(|| format!("{}+{}@social.pero.dev", info.provider, info.provider_uid));

    let username = resolve_unique_username(&mut *tx, &base_username).await?;
    let email = resolve_unique_email(&mut *tx, &base_email).await?;

    let user = UserRepo::create(
        &mut *tx,
        &username,
        &email,
        None,
        info.display_name.as_deref(),
    )
    .await?;

    sqlx::query(
        "INSERT INTO identities (user_id, provider, provider_uid, verified) VALUES ($1, $2, $3, true)",
    )
    .bind(user.id)
    .bind(&info.provider)
    .bind(&info.provider_uid)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    Ok(user)
}

pub async fn bind_social_identity(
    state: &AppState,
    code: &str,
    state_token: &str,
    bind_user_id: &str,
) -> Result<(), AppError> {
    let user_id: uuid::Uuid = bind_user_id
        .parse()
        .map_err(|_| AppError::BadRequest("invalid bind_user id".into()))?;

    let key = format!("social_state:{state_token}");
    let social_state: SocialBindState = cache::get_json(&state.cache, &key)
        .await?
        .ok_or_else(social_state_invalid)?;
    cache::del(&state.cache, &key).await?;

    if social_state.bind_user_id != bind_user_id {
        return Err(social_state_invalid());
    }

    let provider = SocialProviderRepo::find_by_name(&state.db, &social_state.provider)
        .await?
        .ok_or(provider_not_found())?;
    if !provider.enabled {
        return Err(provider_disabled());
    }

    let access_token = userinfo::exchange_code(
        &provider,
        code,
        &format!(
            "{}/sso/social/{}/callback?bind_user={}",
            state.config.oidc.issuer.trim_end_matches('/'),
            social_state.provider,
            bind_user_id
        ),
    )
    .await?;
    let user_info = userinfo::fetch_userinfo(&provider, &access_token).await?;

    let existing =
        IdentityRepo::find_by_provider(&state.db, &user_info.provider, &user_info.provider_uid)
            .await?;
    if let Some(existing_identity) = existing {
        if existing_identity.user_id != user_id {
            return Err(AppError::Conflict(
                "this social account is already linked to another user".into(),
            ));
        }
        return Ok(());
    }

    IdentityRepo::create_oauth(
        &state.db,
        user_id,
        &user_info.provider,
        &user_info.provider_uid,
    )
    .await?;
    Ok(())
}

async fn resolve_unique_username(
    executor: &mut sqlx::PgConnection,
    base: &str,
) -> Result<String, AppError> {
    const MAX_USERNAME_CHARS: usize = 64;

    for i in 0..100u32 {
        let name = username_candidate(base, (i > 0).then_some(i), MAX_USERNAME_CHARS);
        let exists: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE username = $1)")
                .bind(&name)
                .fetch_one(&mut *executor)
                .await?;
        if !exists {
            return Ok(name);
        }
    }
    Err(AppError::Conflict(
        "could not generate unique username".into(),
    ))
}

pub fn username_candidate(base: &str, suffix: Option<u32>, max_len: usize) -> String {
    let suffix = suffix.map(|value| format!("_{value}")).unwrap_or_default();
    let base_len = max_len.saturating_sub(suffix.chars().count());
    let truncated: String = base.chars().take(base_len).collect();
    format!("{truncated}{suffix}")
}

async fn resolve_unique_email(
    executor: &mut sqlx::PgConnection,
    base: &str,
) -> Result<String, AppError> {
    let mut email = base.to_string();
    for i in 0..100u32 {
        let exists: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE email = $1)")
                .bind(&email)
                .fetch_one(&mut *executor)
                .await?;
        if !exists {
            return Ok(email);
        }
        email = format!("{i}_{base}");
    }
    Err(AppError::Conflict("could not generate unique email".into()))
}
