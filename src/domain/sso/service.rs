use crate::domain::identity::UserRepo;
use crate::domain::oauth2::service as oauth2_service;
use crate::domain::oauth2::store::AuthCodeRepo;
use crate::domain::sso::models::{ConsentDecision, SsoSession};
use crate::domain::sso::session;
use crate::shared::error::AppError;
use crate::shared::state::AppState;
use crate::shared::utils::append_query_params;

pub struct ConsentViewData {
    pub client_name: String,
    pub scopes: Vec<String>,
}

pub async fn build_consent_view(
    state: &AppState,
    sso: &SsoSession,
) -> Result<ConsentViewData, AppError> {
    let client = load_valid_authorization_client(state, sso).await?;
    let scopes = granted_scopes_for_display(&client, sso);

    Ok(ConsentViewData {
        client_name: client.client_name,
        scopes,
    })
}

pub async fn handle_consent_action(
    state: &AppState,
    sid: &str,
    sso: &SsoSession,
    decision: ConsentDecision,
    account_sid: Option<&str>,
) -> Result<String, AppError> {
    let params = &sso.authorize_params;

    if decision == ConsentDecision::Deny {
        session::delete(&state.cache, sid).await?;
        return Ok(build_redirect(
            &params.redirect_uri,
            "error=access_denied",
            &params.state,
        ));
    }

    let user_id = sso
        .user_id
        .ok_or(AppError::BadRequest("user not authenticated".into()))?;

    let user = UserRepo::find_by_id(&state.db, user_id).await?
        .ok_or(AppError::Unauthorized)?;

    if !user.is_active() {
        session::delete(&state.cache, sid).await?;
        return Err(AppError::Unauthorized);
    }

    let client = load_valid_authorization_client(state, sso).await?;
    let scopes = granted_scopes(&client, sso);

    let code = uuid::Uuid::new_v4().to_string().replace('-', "");

    AuthCodeRepo::create(
        &state.db,
        &code,
        client.id,
        user_id,
        &params.redirect_uri,
        &scopes,
        Some(&params.code_challenge),
        Some(&params.code_challenge_method),
        params.nonce.as_deref(),
        account_sid,
        sso.auth_time
            .unwrap_or_else(|| chrono::Utc::now().timestamp()),
        state.config.oauth2.auth_code_ttl_minutes,
    )
    .await?;

    session::delete(&state.cache, sid).await?;

    Ok(build_redirect(
        &params.redirect_uri,
        &format!("code={}", urlencoding::encode(&code)),
        &params.state,
    ))
}

fn build_redirect(base: &str, first_param: &str, state: &Option<String>) -> String {
    let params: Vec<(&str, &str)> = first_param.split('&').filter_map(|p| {
        let mut parts = p.splitn(2, '=');
        Some((parts.next()?, parts.next()?))
    }).collect();

    let mut redirect = append_query_params(base, &params).unwrap_or_else(|_| base.to_string());
    if let Some(state) = state {
        redirect.push_str(&format!("&state={}", urlencoding::encode(state)));
    }
    redirect
}

async fn load_valid_authorization_client(
    state: &AppState,
    sso: &SsoSession,
) -> Result<crate::domain::oauth2::models::OAuth2Client, AppError> {
    let params = &sso.authorize_params;
    oauth2_service::validate_authorization_client(
        state,
        &params.client_id,
        &params.redirect_uri,
        &requested_scopes(sso),
    )
    .await
}

fn requested_scopes(sso: &SsoSession) -> Vec<String> {
    crate::shared::utils::parse_scopes(sso.authorize_params.scope.as_deref())
}

fn granted_scopes(
    client: &crate::domain::oauth2::models::OAuth2Client,
    sso: &SsoSession,
) -> Vec<String> {
    let requested = requested_scopes(sso);
    let effective: Vec<String> = if requested.is_empty() {
        client.scopes.clone()
    } else {
        requested
    };
    effective
        .into_iter()
        .filter(|s| client.scopes.iter().any(|cs| cs == s))
        .collect()
}

fn granted_scopes_for_display(
    client: &crate::domain::oauth2::models::OAuth2Client,
    sso: &SsoSession,
) -> Vec<String> {
    let requested = requested_scopes(sso);
    if requested.is_empty() {
        client.scopes.clone()
    } else {
        requested
    }
}
