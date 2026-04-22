use crate::domains::oauth2::repos::{AuthCodeRepo, OAuth2ClientRepo};
use crate::domains::sso::models::{ConsentDecision, SsoSession};
use crate::domains::sso::session;
use crate::shared::constants::oauth2 as oauth2_constants;
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
) -> Result<crate::domains::oauth2::models::OAuth2Client, AppError> {
    let params = &sso.authorize_params;
    let client = OAuth2ClientRepo::find_by_client_id(&state.db, &params.client_id)
        .await?
        .ok_or(AppError::BadRequest("invalid client_id".into()))?;

    if !client.enabled {
        return Err(AppError::BadRequest("client is disabled".into()));
    }
    if !client.allows_grant_type(oauth2_constants::GRANT_TYPE_AUTH_CODE) {
        return Err(AppError::BadRequest(format!(
            "grant_type '{}' not allowed",
            oauth2_constants::GRANT_TYPE_AUTH_CODE
        )));
    }
    if !client.redirect_uris.contains(&params.redirect_uri) {
        return Err(AppError::BadRequest("invalid redirect_uri".into()));
    }

    for scope in requested_scopes(sso) {
        if !client.scopes.contains(&scope) {
            return Err(AppError::BadRequest(format!(
                "scope '{}' not allowed",
                scope
            )));
        }
    }

    Ok(client)
}

fn requested_scopes(sso: &SsoSession) -> Vec<String> {
    sso.authorize_params
        .scope
        .as_deref()
        .map(|scope| scope.split_whitespace().map(String::from).collect())
        .unwrap_or_default()
}

fn granted_scopes(
    client: &crate::domains::oauth2::models::OAuth2Client,
    sso: &SsoSession,
) -> Vec<String> {
    let scopes = requested_scopes(sso);
    if scopes.is_empty() {
        client.scopes.clone()
    } else {
        scopes
    }
}
