use crate::domain::oauth::repo::{OAuth2ClientStore, OAuth2TokenStore};
use crate::domain::oauth::service as oauth2_service;
use crate::domain::sso::models::{ConsentDecision, SsoSession};
use crate::domain::sso::repo::SsoSessionStore;
use crate::domain::user::repo::UserStore;
use crate::shared::error::AppError;
use crate::shared::utils::append_query_params;

pub struct ConsentViewData {
    pub client_name: String,
    pub scopes: Vec<String>,
}

pub async fn build_consent_view(
    clients: &dyn OAuth2ClientStore,
    apps: &dyn crate::domain::app::repo::AppStore,
    _sso_store: &dyn SsoSessionStore,
    sso: &SsoSession,
) -> Result<ConsentViewData, AppError> {
    let client = load_valid_authorization_client(clients, apps, sso).await?;
    let scopes = effective_scopes(&client, sso, false);

    Ok(ConsentViewData {
        client_name: client.client_name,
        scopes,
    })
}

pub async fn handle_consent_action(
    clients: &dyn OAuth2ClientStore,
    apps: &dyn crate::domain::app::repo::AppStore,
    users: &dyn UserStore,
    sso_store: &dyn SsoSessionStore,
    tokens: &dyn OAuth2TokenStore,
    auth_code_ttl_minutes: i64,
    sid: &str,
    sso: &SsoSession,
    decision: ConsentDecision,
    account_sid: Option<&str>,
) -> Result<String, AppError> {
    let params = &sso.authorize_params;

    if decision == ConsentDecision::Deny {
        sso_store.delete(sid).await?;
        return Ok(build_redirect(
            &params.redirect_uri,
            &[("error", "access_denied")],
            &params.state,
        ));
    }

    let user_id = sso
        .user_id
        .ok_or(AppError::BadRequest("user not authenticated".into()))?;

    let user = users
        .find_by_id(user_id)
        .await?
        .ok_or(AppError::Unauthorized)?;

    if !user.is_active() {
        sso_store.delete(sid).await?;
        return Err(AppError::Unauthorized);
    }

    let client = load_valid_authorization_client(clients, apps, sso).await?;
    let scopes = effective_scopes(&client, sso, true);

    let code = uuid::Uuid::new_v4().to_string().replace('-', "");

    tokens
        .create_auth_code(crate::domain::oauth::repo::CreateAuthCodeParams {
            code: code.clone(),
            client_id: client.id,
            user_id,
            redirect_uri: params.redirect_uri.clone(),
            scopes: scopes.clone(),
            code_challenge: params.code_challenge.clone(),
            code_challenge_method: params.code_challenge_method.clone(),
            nonce: params.nonce.clone(),
            sid: account_sid.map(|s| s.to_string()),
            auth_time: sso
                .auth_time
                .unwrap_or_else(|| chrono::Utc::now().timestamp()),
            ttl_minutes: auth_code_ttl_minutes,
        })
        .await?;

    sso_store.delete(sid).await?;

    Ok(build_redirect(
        &params.redirect_uri,
        &[("code", &code)],
        &params.state,
    ))
}

fn build_redirect(base: &str, params: &[(&str, &str)], state: &Option<String>) -> String {
    let mut all_params: Vec<(&str, &str)> = params.to_vec();
    if let Some(s) = state {
        all_params.push(("state", s));
    }
    append_query_params(base, &all_params).unwrap_or_else(|_| base.to_string())
}

async fn load_valid_authorization_client(
    clients: &dyn OAuth2ClientStore,
    apps: &dyn crate::domain::app::repo::AppStore,
    sso: &SsoSession,
) -> Result<crate::domain::oauth::models::OAuth2Client, AppError> {
    let params = &sso.authorize_params;
    oauth2_service::validate_authorization_client(
        clients,
        apps,
        &params.client_id,
        &params.redirect_uri,
        &requested_scopes(sso),
    )
    .await
}

fn requested_scopes(sso: &SsoSession) -> Vec<String> {
    crate::shared::utils::parse_scopes(sso.authorize_params.scope.as_deref())
}

fn effective_scopes(
    client: &crate::domain::oauth::models::OAuth2Client,
    sso: &SsoSession,
    filter_allowed: bool,
) -> Vec<String> {
    let requested = requested_scopes(sso);
    let raw: Vec<String> = if requested.is_empty() {
        client.scopes.clone()
    } else {
        requested
    };
    if filter_allowed {
        raw.into_iter()
            .filter(|s| client.scopes.iter().any(|cs| cs == s))
            .collect()
    } else {
        raw
    }
}
