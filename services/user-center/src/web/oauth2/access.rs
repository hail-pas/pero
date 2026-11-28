//! Interactive recovery for missing application entitlement. Silent requests never enter here.
use axum::{
    Form,
    extract::{Query, State},
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::CookieJar;
use sea_orm::{ConnectionTrait, DbBackend, EntityTrait, Statement, TransactionTrait};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    db::entity::{apps, authorization_requests, oauth_clients, user_app_access, users},
    db::enums::CommonStatus,
    service::{
        application_request, enrollment::ApplicationSource, oauth::OAuthService,
        session::SessionService,
    },
    state::{app::AppState, session::SsoSession},
    web::{error::OAuthError, session::extract_session, util},
};

#[derive(Serialize, Deserialize)]
struct Recovery {
    source: ApplicationSource,
    session_id: Uuid,
    diagnostic: bool,
}

enum RecoveryRequest {
    Pending(SsoSession, Box<authorization_requests::Model>),
    Expired(ApplicationSource),
}

#[derive(Deserialize)]
pub struct Params {
    #[serde(default)]
    token: String,
}
#[derive(Deserialize)]
pub struct Input {
    csrf_token: String,
    token: String,
    action: String,
}
fn key(state: &AppState) -> &[u8] {
    state
        .config
        .sso
        .cookie_signing_secret
        .expose_secret()
        .as_bytes()
}

pub(super) fn redirect(
    state: &AppState,
    jar: CookieJar,
    request: &authorization_requests::Model,
    session_id: Uuid,
) -> Result<(CookieJar, Response), OAuthError> {
    let token = pero_utils::crypto::encode_signed_json(
        &Recovery {
            source: request.into(),
            session_id,
            diagnostic: request.diagnostic_session_id.is_some(),
        },
        key(state),
    )
    .map_err(|_| OAuthError::Unavailable)?;
    let mut url = "/oauth2/authorize/access".to_owned();
    pero_utils::encode::append_query_param(&mut url, "token", &token);
    Ok((jar, Redirect::to(&url).into_response()))
}

async fn load(
    state: &AppState,
    jar: &CookieJar,
    token: &str,
) -> Result<RecoveryRequest, OAuthError> {
    let recovery: Recovery = pero_utils::crypto::decode_signed_json(token, key(state))
        .map_err(|_| OAuthError::BadRequest("Invalid recovery request".into()))?;
    let Some(session) = extract_session(state, jar)
        .await
        .map_err(|_| OAuthError::Unavailable)?
        .filter(|s| s.id == recovery.session_id)
    else {
        return Ok(RecoveryRequest::Expired(recovery.source));
    };
    let request = authorization_requests::Entity::find_by_id(recovery.source.request_id)
        .one(&state.db)
        .await
        .map_err(|_| OAuthError::Unavailable)?
        .filter(|request| {
            request.client_id == recovery.source.client_id
                && request.app_id == recovery.source.app_id
                && request.diagnostic_session_id.is_some() == recovery.diagnostic
                && request
                    .diagnostic_session_id
                    .is_none_or(|id| id == session.id)
                && request.completed_at.is_none()
                && request.expires_at > time::OffsetDateTime::now_utc()
        });
    Ok(match request {
        Some(request) => RecoveryRequest::Pending(session, Box::new(request)),
        None => RecoveryRequest::Expired(recovery.source),
    })
}

fn expired(state: &AppState, jar: CookieJar, login_url: Option<String>) -> Response {
    state
        .web_security()
        .view_with_csrf(jar, "AppAccessDeniedView", |csrf_token| {
            serde_json::json!({
                "csrf_token": csrf_token, "token": "", "app_name": "", "username": "",
                "expired": true, "login_url": login_url,
            })
        })
}

async fn expired_with_source(
    state: &AppState,
    jar: CookieJar,
    source: ApplicationSource,
) -> Response {
    let login_url = match oauth_clients::Entity::find_by_id(source.client_id)
        .one(&state.db)
        .await
    {
        Ok(Some(client)) if client.app_id == source.app_id => {
            crate::web::login_flow::client_login_target(state, client, source.tenant_id, None)
                .await
                .unwrap_or_default()
        }
        _ => None,
    };
    expired(state, jar, login_url)
}

pub async fn get(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(params): Query<Params>,
) -> Response {
    let (request, user_id) = match load(&state, &jar, &params.token).await {
        Ok(RecoveryRequest::Pending(session, request)) => (request, session.user_id),
        Ok(RecoveryRequest::Expired(source)) => {
            return expired_with_source(&state, jar, source).await;
        }
        Err(OAuthError::BadRequest(_)) => return expired(&state, jar, None),
        Err(e) => return e.into_response(),
    };
    let app = match apps::Entity::find_by_id(request.app_id)
        .one(&state.db)
        .await
    {
        Ok(Some(a)) => a,
        Ok(None) => return expired(&state, jar, None),
        Err(e) => return util::dependency_error(e),
    };
    let user = match users::Entity::find_by_id(user_id).one(&state.db).await {
        Ok(Some(u)) => u,
        Ok(None) => return expired(&state, jar, None),
        Err(e) => return util::dependency_error(e),
    };
    let tenant_unavailable = if !app.system
        && let Some(tenant) = request.tenant_id
    {
        match crate::service::tenant_context::eligible(&state.db, user_id, app.id, tenant).await {
            Ok(space) => space.is_none(),
            Err(error) => return util::dependency_error(error),
        }
    } else {
        false
    };
    let (can_request, opens_immediately, granted, application, admission_error) =
        if app.system || tenant_unavailable || request.diagnostic_session_id.is_some() {
            (false, false, false, None, None)
        } else {
            let result = async {
                let policy = application_request::policy(&state.db, app.id).await?;
                let access = user_app_access::Entity::find_by_id((user_id, app.id))
                    .one(&state.db)
                    .await?;
                let application = application_request::current(&state.db, user_id, app.id).await?;
                let granted = access.as_ref().is_some_and(|access| {
                    access.status == CommonStatus::Active && access.admission_origin == "explicit"
                });
                let self_service = app.status == CommonStatus::Active
                    && app.tenant_mode != "organization"
                    && policy.mode != "managed"
                    && !policy.paused
                    && !granted
                    && access.is_none_or(|access| access.status == CommonStatus::Active);
                let admission_error = if self_service {
                    application_request::check_email_domain(&policy.domains, &user).err()
                } else {
                    None
                };
                Ok::<_, crate::service::ManagementError>((
                    self_service && admission_error.is_none(),
                    policy.mode == "open",
                    granted,
                    application,
                    admission_error,
                ))
            }
            .await;
            match result {
                Ok(result) => result,
                Err(error) => return util::management_response(Err(error)),
            }
        };
    state
        .web_security()
        .view_with_csrf(jar, "AppAccessDeniedView", |csrf_token| {
            serde_json::json!({
                "csrf_token": csrf_token, "token": params.token, "app_name": app.name,
                "username": user.username, "expired": false,
                "diagnostic": request.diagnostic_session_id.is_some(),
                "can_request": can_request, "opens_immediately": opens_immediately,
                "tenant_unavailable": tenant_unavailable,
                "admission_error": admission_error,
                "granted": granted, "application": application,
            })
        })
}

pub async fn post(
    State(state): State<AppState>,
    jar: CookieJar,
    Form(input): Form<Input>,
) -> Response {
    if let Some(e) = util::verify_csrf_or_json_error(&jar, &input.csrf_token, &state) {
        return e;
    }
    if !matches!(
        input.action.as_str(),
        "retry" | "other" | "cancel" | "join" | "withdraw"
    ) {
        return pero_api_axum::json_error("invalid_request");
    }
    let (session, request) = match load(&state, &jar, &input.token).await {
        Ok(RecoveryRequest::Pending(session, request)) => (session, request),
        Ok(RecoveryRequest::Expired(source)) => {
            return expired_with_source(&state, jar, source).await;
        }
        Err(OAuthError::BadRequest(_)) => return expired(&state, jar, None),
        Err(e) => return e.into_response(),
    };
    if input.action == "other" && request.diagnostic_session_id.is_some() {
        return pero_api_axum::json_error("invalid_request");
    }
    if input.action == "cancel" {
        let result = state
            .oauth_service()
            .finish_authorization_request(&state.db, request.id, &session, false)
            .await;
        return match result {
            Ok(true) => Redirect::to("/account/profile").into_response(),
            Ok(false) => expired_with_source(&state, jar, (&*request).into()).await,
            Err(e) => util::dependency_error(e),
        };
    }
    if matches!(input.action.as_str(), "join" | "withdraw") {
        let result = application_action(&state, &session, &request, &input.action).await;
        match result {
            Ok(true) => {}
            Ok(false) => return get(State(state), jar, Query(Params { token: input.token })).await,
            Err(error @ crate::service::ManagementError::Invalid("unauthorized")) => {
                return match crate::web::account::mfa::pending_target(&state, &jar).await {
                    Ok(Some(target)) => {
                        super::authorize::resume_after_mfa(&state, &jar, request.id, target)
                            .await
                            .into_response()
                    }
                    Ok(None) => util::management_response(Err(error)),
                    Err(response) => *response,
                };
            }
            Err(error) => return util::management_response(Err(error)),
        }
    }
    // Validate current client configuration before resuming a pending request.
    let result = async {
        if input.action == "other" {
            let db_error = |error| OAuthError::Internal(crate::db::error::to_app_error(error));
            let txn = state.db.begin().await.map_err(db_error)?;
            OAuthService::lock_pending_authorization_policy(&txn, &request).await?;
            // Issuance also locks the session before the request.
            if !SessionService::revoke_login_state_in_db(&txn, session.id, "account_switch")
                .await
                .map_err(db_error)?
            {
                return Err(OAuthError::BadRequest(
                    "Authorization session expired".into(),
                ));
            }
            let pending = txn
                .query_one_raw(Statement::from_sql_and_values(
                    DbBackend::Postgres,
                    "SELECT id FROM authorization_requests WHERE id=$1 AND completed_at IS NULL
                     AND expires_at>clock_timestamp() FOR UPDATE",
                    [request.id.into()],
                ))
                .await
                .map_err(db_error)?;
            if pending.is_none() {
                return Err(OAuthError::BadRequest("Authorization request ended".into()));
            }
            let (jar, response) =
                super::authorize::pending_redirect(&state, &jar, request.id).await?;
            txn.commit().await.map_err(db_error)?;
            Ok((
                super::select_account::clear_session_cookie(&state, jar),
                response,
            ))
        } else {
            super::authorize::resolve_pending_authorization(&state, &jar, &request, true).await
        }
    }
    .await;
    match result {
        Ok(v) => v.into_response(),
        Err(OAuthError::BadRequest(_)) => expired(&state, jar, None),
        Err(e) => e.into_response(),
    }
}

async fn application_action(
    state: &AppState,
    session: &SsoSession,
    request: &authorization_requests::Model,
    action: &str,
) -> Result<bool, crate::service::ManagementError> {
    use crate::service::ManagementError as Error;
    if request.diagnostic_session_id.is_some() {
        return Err(Error::Invalid("enrollment_unavailable"));
    }
    state
        .oauth_service()
        .validate_pending_authorization(request)
        .await
        .map_err(|error| match error {
            crate::service::oauth::OAuthError::Internal(error) => Error::Credential(error),
            _ => Error::Invalid("enrollment_unavailable"),
        })?;
    if action == "withdraw" {
        application_request::withdraw(state, session, request.app_id).await?;
        return Ok(false);
    }
    if let Some(tenant) = request.tenant_id
        && crate::service::tenant_context::eligible(
            &state.db,
            session.user_id,
            request.app_id,
            tenant,
        )
        .await?
        .is_none()
    {
        return Err(Error::Invalid("enrollment_unavailable"));
    }
    application_request::submit(state, session, request.app_id).await
}
