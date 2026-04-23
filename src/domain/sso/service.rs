use crate::domain::oauth2::store::AuthCodeRepo;
use crate::domain::oauth2::service as oauth2_service;
use crate::domain::sso::models::{ConsentDecision, SsoSession};
use crate::domain::sso::session;
use crate::shared::error::AppError;
use crate::shared::state::AppState;

pub struct ConsentViewData {
    pub client_name: String,
    pub scopes: Vec<String>,
}

pub async fn build_consent_view(
    state: &AppState,
    sso: &SsoSession,
) -> Result<ConsentViewData, AppError> {
    let client = load_valid_authorization_client(state, sso).await?;
    let scopes = requested_scopes(sso);

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
    let mut redirect = format!("{base}?{first_param}");
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
    let scopes = requested_scopes(sso);
    if scopes.is_empty() {
        client.scopes.clone()
    } else {
        scopes
    }
}
