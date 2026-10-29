//! Diagnostic state and token verification. HTTP handlers own authentication and rendering.
use crate::{
    cache::key::IntegrationTestValue as TestFlow,
    db::{
        entity::{authorization_requests, oauth_clients, refresh_tokens},
        enums::{CommonStatus, OauthClientType},
    },
    service::{
        ManagementError,
        token::{TokenEndpointResult, TokenRequest, TokenService},
    },
    state::{app::AppState, session::SsoSession},
};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, Set};
use uuid::Uuid;
pub fn callback_uri(state: &AppState) -> String {
    pero_utils::oauth::url::issuer_endpoint(&state.config.oidc.issuer, "oauth2/diagnostic/callback")
}
async fn client(
    state: &AppState,
    app_id: Uuid,
    id: Uuid,
) -> Result<oauth_clients::Model, ManagementError> {
    oauth_clients::Entity::find_by_id(id)
        .filter(oauth_clients::Column::AppId.eq(app_id))
        .one(&state.db)
        .await?
        .ok_or(ManagementError::Invalid("not_found"))
}
pub async fn flow(
    state: &AppState,
    ticket: &str,
    session: &crate::state::session::SsoSession,
    app: Uuid,
) -> Result<TestFlow, ManagementError> {
    let key = crate::cache::key::integration_test.key(&pero_utils::crypto::sha256_hex(ticket))?;
    state
        .cache
        .get(key)
        .await?
        .filter(|v| v.user_id == session.user_id && v.session_id == session.id && v.app_id == app)
        .ok_or(ManagementError::Invalid("integration_test_expired"))
}

pub async fn start(
    state: &AppState,
    session: &SsoSession,
    app_id: Uuid,
    client_id: Uuid,
) -> Result<String, ManagementError> {
    let c = client(state, app_id, client_id).await?;

    if c.status != CommonStatus::Active
        || !c.redirect_uris.contains(&callback_uri(state))
        || !c.scopes.iter().any(|s| s == "openid")
        || !c.grant_types.iter().any(|s| s == "authorization_code")
    {
        return Err(ManagementError::Invalid(
            "integration_configuration_required",
        ));
    }
    let pair = pero_utils::oauth::pkce::PkcePair::generate();
    let ticket = pero_utils::crypto::generate_nonce();
    let value = TestFlow {
        user_id: session.user_id,
        session_id: session.id,
        app_id,
        client_id: c.id,
        verifier: pair.code_verifier,
        nonce: pero_utils::crypto::generate_nonce(),
        code: None,
    };
    // Validate app policy and create the internal request directly; the public
    // authorize endpoint always creates ordinary requests regardless of state.
    state
        .oauth_service()
        .validate_app(&c)
        .await
        .map_err(|error| match error {
            super::oauth::OAuthError::Internal(error) => ManagementError::Credential(error),
            _ => ManagementError::Invalid("integration_configuration_required"),
        })?;
    let request = crate::db::helper::auth_request::create(
        &state.db,
        crate::db::helper::auth_request::CreateParams {
            diagnostic_session_id: Some(session.id),
            client_id: c.id,
            app_id,
            redirect_uri: callback_uri(state),
            scopes: vec!["openid".into()],
            client_state: Some(ticket.clone()),
            nonce: Some(value.nonce.clone()),
            code_challenge: Some(pair.code_challenge),
            code_challenge_method: Some(crate::db::enums::CodeChallengeMethod::S256),
            prompt: Some("consent".into()),
            max_age: None,
            login_hint: None,
            expires_at: time::OffsetDateTime::now_utc()
                + time::Duration::seconds(state.config.oauth2.auth_code_ttl_seconds as i64),
        },
    )
    .await?;
    state
        .cache
        .set(
            crate::cache::key::integration_test.key(&pero_utils::crypto::sha256_hex(&ticket))?,
            &value,
        )
        .await?;
    let mut url = pero_utils::oauth::url::issuer_endpoint(
        &state.config.oidc.issuer,
        "oauth2/diagnostic/authorize",
    );
    pero_utils::encode::append_query_param(&mut url, "request", &request.id.to_string());
    Ok(url)
}
pub async fn finish(
    state: &AppState,
    session: &SsoSession,
    app_id: Uuid,
    client_id: Uuid,
    ticket: &str,
    secret: Option<String>,
    source: &str,
) -> Result<(), ManagementError> {
    let c = client(state, app_id, client_id).await?;
    let value = flow(state, ticket, session, app_id).await?;
    if value.client_id != c.id {
        return Err(ManagementError::Invalid("invalid_request"));
    }
    let ticket_key =
        crate::cache::key::integration_test.key(&pero_utils::crypto::sha256_hex(ticket))?;
    // A successful exchange consumes the authorization code even if later checks fail.
    // Consume the diagnostic state before exchanging, preventing accidental code replay.
    if state.cache.take(ticket_key.clone()).await?.is_none() {
        return Err(ManagementError::Invalid("integration_test_expired"));
    }
    let code = value
        .code
        .clone()
        .ok_or(ManagementError::Invalid("integration_test_expired"))?;
    let request = TokenRequest {
        grant_type: "authorization_code".into(),
        code: Some(code.clone()),
        redirect_uri: Some(callback_uri(state)),
        code_verifier: Some(value.verifier.clone()),
        refresh_token: None,
        scope: None,
        client_id: c.identifier.clone(),
        client_secret: if c.r#type == OauthClientType::Public {
            None
        } else {
            secret
        },
    };
    let token = match TokenService::new(state).token(&request, source).await {
        TokenEndpointResult::Success(token) => token,
        TokenEndpointResult::Unauthorized(_) => {
            // Client authentication failed before any authorization code was used.
            state.cache.set(ticket_key, &value).await?;
            return Err(ManagementError::Invalid("integration_invalid_secret"));
        }
        TokenEndpointResult::Error { code, .. } => {
            if matches!(
                code,
                pero_error::protocol::oauth::OAuth2ErrorCode::TemporarilyUnavailable
                    | pero_error::protocol::oauth::OAuth2ErrorCode::ServerError
            ) {
                return Err(ManagementError::Dependency(sea_orm::DbErr::Custom(
                    "Diagnostic token exchange unavailable; start a new test".into(),
                )));
            }
            return Err(ManagementError::Validation(code.as_str().into()));
        }
    };
    // Retire only the diagnostic refresh token, never the application's other grants.
    if let Some(refresh) = &token.refresh_token {
        refresh_tokens::Entity::update_many()
            .set(refresh_tokens::ActiveModel {
                revoked_at: Set(Some(time::OffsetDateTime::now_utc())),
                revoke_reason: Set(Some("integration_test".into())),
                ..Default::default()
            })
            .filter(refresh_tokens::Column::TokenHash.eq(pero_utils::crypto::sha256_hex(refresh)))
            .exec(&state.db)
            .await?;
    }
    let id_token = token
        .id_token
        .as_deref()
        .ok_or(ManagementError::Invalid("integration_token_invalid"))?;
    let kid = pero_utils::oauth::jwt::decode_jwt_kid(id_token)
        .map_err(|_| ManagementError::Invalid("integration_token_invalid"))?;
    let key = crate::db::helper::signing_key::find_verification_key_by_kid(&state.db, &kid)
        .await?
        .ok_or(ManagementError::Invalid("integration_token_invalid"))?;
    let claims = pero_utils::oauth::jwt::verify_id_token(
        id_token,
        &state.config.oidc.issuer,
        &c.identifier,
        &key.public_key_pem,
    )
    .map_err(|_| ManagementError::Invalid("integration_token_invalid"))?;
    if claims.nonce.as_deref() != Some(value.nonce.as_str())
        || claims.sub != session.user_id.to_string()
        || claims.sid.as_deref() != Some(session.id.to_string().as_str())
        || claims.at_hash.as_deref()
            != Some(pero_utils::oauth::jwt::oidc_hash(&token.access_token).as_str())
        || claims.c_hash.as_deref() != Some(pero_utils::oauth::jwt::oidc_hash(&code).as_str())
        || crate::service::token_status::active_access(state, &token.access_token)
            .await?
            .is_none()
    {
        return Err(ManagementError::Invalid("integration_token_invalid"));
    }

    Ok(())
}
pub async fn complete_callback(
    state: &AppState,
    session: &SsoSession,
    ticket: &str,
    code: Option<String>,
    error: Option<String>,
) -> Result<String, ManagementError> {
    let key = crate::cache::key::integration_test.key(&pero_utils::crypto::sha256_hex(ticket))?;
    state
        .cache
        .get(key.clone())
        .await?
        .filter(|v| v.session_id == session.id && v.user_id == session.user_id && v.code.is_none())
        .ok_or(ManagementError::Invalid("integration_test_expired"))?;
    let mut value = state
        .cache
        .take(key)
        .await?
        .ok_or(ManagementError::Invalid("integration_test_expired"))?;
    // The preceding ownership check must also hold for the value actually consumed.
    if value.session_id != session.id || value.user_id != session.user_id {
        return Err(ManagementError::Invalid("unauthorized"));
    }
    let mut url = format!(
        "/dashboard/apps/{}/integration?client={}",
        value.app_id, value.client_id
    );
    if let Some(error) = error {
        pero_utils::encode::append_query_param(
            &mut url,
            "test_error",
            if error == "access_denied" {
                "access_denied"
            } else {
                "failed"
            },
        );
    } else {
        value.code = Some(
            code.filter(|c| !c.is_empty())
                .ok_or(ManagementError::Invalid("integration_authorization_failed"))?,
        );
        let ticket = pero_utils::crypto::generate_nonce();
        state
            .cache
            .set(
                crate::cache::key::integration_test
                    .key(&pero_utils::crypto::sha256_hex(&ticket))?,
                &value,
            )
            .await?;
        pero_utils::encode::append_query_param(&mut url, "test", &ticket);
    }

    Ok(url)
}
/// Read only the initiating session's pending internal request.
pub async fn authorization_request(
    state: &AppState,
    session: &SsoSession,
    id: Uuid,
) -> Result<authorization_requests::Model, ManagementError> {
    authorization_requests::Entity::find_by_id(id)
        .filter(authorization_requests::Column::DiagnosticSessionId.eq(session.id))
        .filter(authorization_requests::Column::CompletedAt.is_null())
        .filter(authorization_requests::Column::ExpiresAt.gt(time::OffsetDateTime::now_utc()))
        .one(&state.db)
        .await?
        .ok_or(ManagementError::Invalid("integration_test_expired"))
}
