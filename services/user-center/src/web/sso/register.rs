use crate::db::entity::authorization_requests;
use crate::{service::enrollment, state::app::AppState, web::util};
use axum::{
    Form,
    extract::{Query, State},
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::{CookieJar, cookie::Cookie};
use enrollment::SocialProof;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
const SOCIAL_COOKIE: &str = "pero_enrollment_identity";
const FLOW_COOKIE: &str = "pero_enrollment";
const INVITATION_COOKIE: &str = "pero_tenant_invitation";
const REQUEST_CONTEXT_COOKIE: &str = "pero_enrollment_request";
const PROGRESS_COOKIE: &str = "pero_enrollment_progress";
pub(crate) const LOGIN_PATH: &str = "/sso/register/login";
#[derive(Default, Deserialize)]
pub struct Params {
    pub token: Option<String>,
    pub invitation: Option<String>,
    pub entry: Option<String>,
    pub source: Option<String>,
    pub error: Option<String>,
}
#[derive(Default, Deserialize)]
pub struct Input {
    #[serde(default)]
    pub csrf_token: String,
    #[serde(default)]
    pub action: String,
    pub flow: String,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub phone: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    pub app: Option<Uuid>,
}
#[derive(Serialize)]
struct View {
    csrf_token: String,
    mode: String,
    app: Option<Uuid>,
    email: String,
    phone: String,
    app_name: String,
    status: String,
    reason: String,
    social: bool,
    tenant_name: String,
    tenant_invitation: bool,
    existing_account: bool,
    signed_in: bool,
    matching_account: bool,
    allowed_methods: Vec<&'static str>,
    providers: Vec<super::dto::SocialProvider>,
    flow: String,
    can_act: bool,
    can_resend: bool,
    already_admitted: bool,
    error: String,
    expires_at: Option<String>,
}
pub(crate) fn clear_flow(jar: CookieJar) -> CookieJar {
    // Requests outside /sso do not carry these cookies. Explicit expiration
    // is required even when the incoming CookieJar has no original cookie.
    [
        FLOW_COOKIE,
        SOCIAL_COOKIE,
        INVITATION_COOKIE,
        REQUEST_CONTEXT_COOKIE,
        PROGRESS_COOKIE,
    ]
    .into_iter()
    .fold(jar, |jar, name| {
        jar.add(pero_api_axum::cookie::clear_cookie_with_domain(
            name, "/sso", None,
        ))
    })
}

#[derive(Serialize, Deserialize)]
struct Progress {
    id: Uuid,
    expires: i64,
    verified: bool,
}

fn signing_key(state: &AppState) -> &[u8] {
    state
        .config
        .sso
        .cookie_signing_secret
        .expose_secret()
        .as_bytes()
}

pub(super) async fn login_registration_url(
    state: &AppState,
    jar: &CookieJar,
) -> Result<String, crate::service::ManagementError> {
    let Some(request) = active_request(state, jar)
        .await?
        .filter(|request| request.diagnostic_session_id.is_none())
    else {
        return Ok("/sso/register?entry=platform".to_owned());
    };
    let source = crate::web::login_flow::sign_enrollment_continuation(state, &request, None, None)
        .map_err(|_| crate::service::ManagementError::Invalid("enrollment_unavailable"))?;
    let mut url = "/sso/register?entry=application".to_owned();
    pero_utils::encode::append_query_param(&mut url, "source", &source);
    Ok(url)
}

pub(crate) fn has_registration(state: &AppState, jar: &CookieJar) -> bool {
    flow_token(jar).is_some() || tenant_token(jar).is_some() || progress_claim(state, jar).is_some()
}

fn progress_claim(state: &AppState, jar: &CookieJar) -> Option<Progress> {
    let cookie = jar.get(PROGRESS_COOKIE)?;
    let proof: Progress =
        pero_utils::crypto::decode_signed_json(cookie.value(), signing_key(state)).ok()?;
    (proof.expires > time::OffsetDateTime::now_utc().unix_timestamp()).then_some(proof)
}

fn with_progress(
    state: &AppState,
    jar: CookieJar,
    id: Uuid,
    verified: bool,
) -> Result<CookieJar, crate::service::ManagementError> {
    let value = pero_utils::crypto::encode_signed_json(
        &Progress {
            id,
            verified,
            expires: (time::OffsetDateTime::now_utc() + time::Duration::days(7)).unix_timestamp(),
        },
        signing_key(state),
    )
    .map_err(|_| crate::service::ManagementError::Invalid("enrollment_unavailable"))?;
    Ok(jar.add(registration_cookie(
        state,
        PROGRESS_COOKIE,
        value,
        time::Duration::days(7),
    )))
}

fn registration_cookie(
    state: &AppState,
    name: &'static str,
    value: String,
    ttl: time::Duration,
) -> Cookie<'static> {
    Cookie::build((name, value))
        .path("/sso")
        .http_only(true)
        .secure(state.config.sso.cookie_secure)
        .same_site(axum_extra::extract::cookie::SameSite::Lax)
        .max_age(ttl)
        .build()
}

pub(crate) fn flow_binding(state: &AppState, jar: &CookieJar) -> String {
    let cookie_value = |name| jar.get(name).map(Cookie::value).filter(|v| !v.is_empty());
    let value = if let Some(token) = tenant_token(jar) {
        format!("invitation:{token}")
    } else if let Some(token) = flow_token(jar) {
        format!("enrollment:{token}")
    } else if let Some(progress) = cookie_value(PROGRESS_COOKIE) {
        format!("progress:{progress}")
    } else if let Some(request) = cookie_value(REQUEST_CONTEXT_COOKIE) {
        format!("request:{request}")
    } else {
        "platform".to_owned()
    };
    let proof = cookie_value(SOCIAL_COOKIE).unwrap_or_default();
    pero_utils::crypto::hmac_sha256(format!("{value}:{proof}").as_bytes(), signing_key(state))
}

pub(crate) fn flow_matches(state: &AppState, jar: &CookieJar, flow: Option<&str>) -> bool {
    flow.is_some_and(|flow| {
        pero_utils::crypto::constant_time_eq(flow.as_bytes(), flow_binding(state, jar).as_bytes())
    })
}

// Keep the initiating client beyond the short-lived OAuth nonce, so an
// expired authorization cannot silently become a platform registration.
#[derive(Serialize, Deserialize)]
struct RequestContext {
    client_id: Uuid,
    request_id: Uuid,
    tenant_id: Option<Uuid>,
}

pub(crate) fn request_context_cookie(
    state: &AppState,
    request: &authorization_requests::Model,
) -> Result<Cookie<'static>, crate::service::ManagementError> {
    let value = pero_utils::crypto::encode_signed_json(
        &RequestContext {
            client_id: request.client_id,
            request_id: request.id,
            tenant_id: request.tenant_id,
        },
        signing_key(state),
    )
    .map_err(|_| crate::service::ManagementError::Invalid("enrollment_unavailable"))?;
    Ok(registration_cookie(
        state,
        REQUEST_CONTEXT_COOKIE,
        value,
        time::Duration::days(1),
    ))
}

fn request_context(state: &AppState, jar: &CookieJar) -> Option<RequestContext> {
    let value = jar.get(REQUEST_CONTEXT_COOKIE)?.value();
    pero_utils::crypto::decode_signed_json(value, signing_key(state)).ok()
}

pub(crate) fn request_context_client(state: &AppState, jar: &CookieJar) -> Option<Uuid> {
    request_context(state, jar).map(|ctx| ctx.client_id)
}

pub(crate) async fn active_request(
    state: &AppState,
    jar: &CookieJar,
) -> Result<Option<authorization_requests::Model>, crate::service::ManagementError> {
    let cookies = state.cookie_factory();
    let Some(cookie) = jar.get(&cookies.nonce_cookie_name()) else {
        return Ok(None);
    };
    let Ok(key) = crate::cache::key::pending_req.key(cookie.value()) else {
        return Ok(None);
    };
    let Some(value) = state
        .cache
        .get::<crate::cache::key::PendingReqValue>(key)
        .await?
    else {
        return Ok(None);
    };
    let Ok(id) = Uuid::parse_str(&value.auth_request_id) else {
        return Ok(None);
    };
    Ok(authorization_requests::Entity::find_by_id(id)
        .one(&state.db)
        .await?
        .filter(|r| r.completed_at.is_none() && r.expires_at > time::OffsetDateTime::now_utc()))
}

pub(crate) fn tenant_token(jar: &CookieJar) -> Option<&str> {
    jar.get(INVITATION_COOKIE)
        .map(|c| c.value())
        .filter(|value| !value.is_empty())
}

pub fn flow_token(jar: &CookieJar) -> Option<&str> {
    jar.get(FLOW_COOKIE)
        .map(|c| c.value())
        .filter(|value| !value.is_empty())
}
fn social_proof(state: &AppState, jar: &CookieJar) -> Option<SocialProof> {
    jar.get(SOCIAL_COOKIE)
        .and_then(|c| pero_utils::crypto::decode_signed_json(c.value(), signing_key(state)).ok())
}

fn with_social_proof(
    state: &AppState,
    jar: CookieJar,
    proof: &SocialProof,
) -> Result<CookieJar, crate::service::ManagementError> {
    let value = pero_utils::crypto::encode_signed_json(proof, signing_key(state))
        .map_err(|_| crate::service::ManagementError::Invalid("enrollment_unavailable"))?;
    Ok(jar.add(registration_cookie(
        state,
        SOCIAL_COOKIE,
        value,
        time::Duration::minutes(10),
    )))
}

pub async fn get(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(query): Query<Params>,
) -> Response {
    if let Some(token) = query.invitation {
        if let Err(e) = crate::service::tenant::invitation_progress(&state.db, &token).await {
            if matches!(e, crate::service::ManagementError::Invalid("not_found")) {
                return render_current(&state, jar, "invalid_invitation").await;
            }
            return util::management_response(Err(e));
        }
        let jar = clear_flow(jar);
        let cookie = registration_cookie(&state, INVITATION_COOKIE, token, time::Duration::days(7));
        return (jar.add(cookie), Redirect::to("/sso/register")).into_response();
    }
    if let Some(token) = query.token {
        return enter_enrollment(&state, jar, token).await;
    }
    if query.entry.as_deref() == Some("application") {
        let Some(source) = query
            .source
            .as_deref()
            .and_then(|value| crate::web::login_flow::enrollment_continuation(&state, value))
        else {
            return render(&state, jar, None, "enrollment_request_expired").await;
        };
        return match active_request(&state, &jar).await {
            Ok(Some(request))
                if request.id == source.request_id
                    && request.app_id == source.app_id
                    && request.client_id == source.client_id
                    && request.diagnostic_session_id.is_none() =>
            {
                match application_context_cookie(&state, &request).await {
                    Ok(cookie) => {
                        (clear_flow(jar).add(cookie), Redirect::to("/sso/register")).into_response()
                    }
                    Err(crate::service::ManagementError::Invalid(code)) => {
                        render(&state, clear_flow(jar), None, code).await
                    }
                    Err(e) => util::management_response(Err(e)),
                }
            }
            Ok(Some(_)) => render(&state, jar, None, "enrollment_flow_changed").await,
            Ok(None) => {
                let target =
                    crate::web::login_flow::enrollment_fallback(&state, &source, Some("expired"))
                        .await;
                (jar, Redirect::to(&target)).into_response()
            }
            Err(e) => util::management_response(Err(e)),
        };
    }
    if query.entry.as_deref() == Some("platform") {
        return (clear_flow(jar), Redirect::to("/sso/register")).into_response();
    }
    render_current(&state, jar, query.error.as_deref().unwrap_or("")).await
}

async fn render_current(state: &AppState, jar: CookieJar, error: &str) -> Response {
    if tenant_token(&jar).is_some() {
        return render_invitation(state, jar, error).await;
    }
    let request = match registration_request(state, &jar).await {
        Ok(request) => request,
        Err(e) => return util::management_response(Err(e)),
    };
    let app = request.as_ref().map(|r| r.app_id);
    if request.is_none()
        && flow_token(&jar).is_none()
        && progress_claim(state, &jar).is_none()
        && request_context_client(state, &jar).is_some()
    {
        return cancel_registration(state, jar, true).await;
    }
    let error = if request
        .as_ref()
        .is_some_and(|request| request.tenant_id.is_some())
        && !has_registration(state, &jar)
    {
        "enrollment_organization_required"
    } else {
        error
    };
    render(state, jar, app, error).await
}

pub(crate) async fn application_context_cookie(
    state: &AppState,
    request: &authorization_requests::Model,
) -> Result<Cookie<'static>, crate::service::ManagementError> {
    crate::db::entity::oauth_clients::Entity::find_by_id(request.client_id)
        .one(&state.db)
        .await?
        .filter(|c| {
            c.app_id == request.app_id
                && c.status == crate::db::enums::CommonStatus::Active
                && c.login_uri
                    .as_deref()
                    .is_some_and(crate::service::client::valid_login_uri)
        })
        .ok_or(crate::service::ManagementError::Invalid(
            "enrollment_client_unavailable",
        ))?;
    request_context_cookie(state, request)
}

pub(crate) async fn registration_request(
    state: &AppState,
    jar: &CookieJar,
) -> Result<Option<authorization_requests::Model>, crate::service::ManagementError> {
    let Some(context) = request_context(state, jar) else {
        return Ok(None);
    };
    Ok(active_request(state, jar).await?.filter(|r| {
        r.id == context.request_id
            && r.client_id == context.client_id
            && r.diagnostic_session_id.is_none()
    }))
}
pub(crate) async fn enter_enrollment(state: &AppState, jar: CookieJar, token: String) -> Response {
    let row = match enrollment::progress_by_token(&state.db, &token).await {
        Ok(row) => row,
        Err(crate::service::ManagementError::Invalid(_)) if flow_token(&jar) == Some(&token) => {
            return render_current(state, jar, "").await;
        }
        Err(crate::service::ManagementError::Invalid(_)) => {
            // An invalid link must not discard another active registration.
            return render_current(state, jar, "enrollment_unavailable").await;
        }
        Err(e) => return util::management_response(Err(e)),
    };
    let proof_cookie = jar
        .get(SOCIAL_COOKIE)
        .cloned()
        .filter(|_| social_proof(state, &jar).is_some_and(|proof| proof.matches(&row)));
    let jar = clear_flow(jar).add(registration_cookie(
        state,
        FLOW_COOKIE,
        token,
        time::Duration::days(7),
    ));
    let mut jar = match with_progress(state, jar, row.id, row.verified_at.is_some()) {
        Ok(jar) => jar,
        Err(e) => return util::management_response(Err(e)),
    };
    if let Some(cookie) = proof_cookie {
        jar = jar.add(cookie);
    }
    (jar, Redirect::to("/sso/register")).into_response()
}

async fn render(state: &AppState, jar: CookieJar, app: Option<Uuid>, error: &str) -> Response {
    let mut can_act = false;
    let progress = progress_claim(state, &jar);
    let row = if let Some(token) = flow_token(&jar) {
        match enrollment::progress_by_token(&state.db, token).await {
            Ok(r) => {
                can_act = true;
                Some(r)
            }
            Err(crate::service::ManagementError::Invalid(_)) => None,
            Err(e) => return util::management_response(Err(e)),
        }
    } else {
        None
    };
    let row = if row.is_none() {
        match progress.as_ref() {
            Some(claim) => match enrollment::progress(&state.db, claim.id).await {
                Ok(r) => Some(r),
                Err(crate::service::ManagementError::Invalid(_)) => None,
                Err(e) => return util::management_response(Err(e)),
            },
            None => None,
        }
    } else {
        row
    };
    let jar = if row.is_none() && (flow_token(&jar).is_some() || jar.get(PROGRESS_COOKIE).is_some())
    {
        [FLOW_COOKIE, PROGRESS_COOKIE, SOCIAL_COOKIE]
            .into_iter()
            .fold(jar, |jar, name| {
                jar.remove(Cookie::build(name).path("/sso"))
            })
    } else {
        jar
    };
    let may_disclose = can_act || progress.as_ref().is_some_and(|p| p.verified);
    let app = row.as_ref().map(|r| r.app_id).unwrap_or(app);
    let terminal = row.as_ref().is_some_and(|r| {
        matches!(
            r.status.as_str(),
            "completed" | "rejected" | "revoked" | "expired"
        )
    });
    let policy = if let Some(row) = row.as_ref().filter(|_| !terminal) {
        enrollment::check(&state.db, row).await
    } else {
        enrollment::policy(&state.db, if terminal { None } else { app }).await
    };
    let (p, blocked) = match policy {
        Ok(p) => (Some(p), ""),
        Err(crate::service::ManagementError::Invalid(code)) => (None, code),
        Err(e) => return util::management_response(Err(e)),
    };
    let mut organization_only = false;
    let app_name = if let Some(id) = app {
        match crate::db::entity::apps::Entity::find_by_id(id)
            .one(&state.db)
            .await
        {
            Ok(Some(app)) => {
                organization_only = app.tenant_mode == "organization";
                app.name
            }
            Ok(None) => String::new(),
            Err(e) => return util::dependency_error(e),
        }
    } else {
        String::new()
    };
    let proof = social_proof(state, &jar);
    let entry_blocked = matches!(
        error,
        "enrollment_organization_required"
            | "enrollment_client_unavailable"
            | "enrollment_request_expired"
            | "enrollment_flow_changed"
    );
    let social_only =
        row.as_ref().is_none() && proof.as_ref().is_some_and(|p| p.is_fresh() && p.app == app);
    let mut allowed_methods = Vec::new();
    if state.config.notification.available("email") {
        allowed_methods.push("email");
    }
    if !social_only
        && p.as_ref().is_some_and(|p| p.domains.is_empty())
        && state.config.notification.available("phone")
    {
        allowed_methods.push("phone");
    }
    let offer_providers = if let Some(row) = &row {
        can_act && row.status == "ready" && row.provider_id.is_some()
    } else {
        !social_only
            && p.as_ref()
                .is_some_and(|p| p.mode == "self_service" && !p.emergency_stop)
            && !organization_only
            && state.config.notification.available("email")
            && !entry_blocked
    };
    let providers = if offer_providers {
        match registration_providers(state, row.as_ref().and_then(|r| r.provider_id)).await {
            Ok(v) => v,
            Err(e) => return util::dependency_error(e),
        }
    } else {
        vec![]
    };
    let session = match registration_session(state, &jar).await {
        Ok(v) => v,
        Err(e) => return *e,
    };
    let existing = if let Some(row) = row.as_ref().filter(|row| {
        can_act
            && row.verified_at.is_some()
            && matches!(row.status.as_str(), "ready" | "pending_approval")
    }) {
        match enrollment::existing_account(&state.db, row).await {
            Ok(v) => v,
            Err(e) => return util::dependency_error(e),
        }
    } else {
        None
    };
    let matching_account = session.as_ref().is_some_and(|s| {
        existing.as_ref().is_some_and(|user| s.user_id == user.id)
            || row
                .as_ref()
                .is_some_and(|r| r.completed_user_id == Some(s.user_id))
    });
    let contact_changed = row.as_ref().is_some_and(|row| {
        can_act
            && row.verified_at.is_some()
            && !terminal
            && enrollment::requires_existing_account(row)
            && (existing.is_none()
                || row
                    .requested_user_id
                    .is_some_and(|id| existing.as_ref().map(|u| u.id) != Some(id)))
    });
    let already_admitted = if let Some(user) = existing.as_ref().filter(|_| matching_account) {
        match enrollment::already_admitted(&state.db, user.id, app).await {
            Ok(v) => v,
            Err(e) => return util::management_response(Err(e)),
        }
    } else {
        false
    };
    let flow = flow_binding(state, &jar);
    let (jar, csrf_token) = state.web_security().ensure_csrf(jar);
    util::view_response(
        "EnrollmentView",
        View {
            csrf_token,
            app,
            mode: if p.as_ref().is_none_or(|p| p.emergency_stop) || contact_changed || entry_blocked
            {
                "closed".into()
            } else if organization_only && row.is_none() {
                "invite_only".into()
            } else {
                p.map_or_else(String::new, |p| p.mode)
            },
            app_name,
            email: row
                .as_ref()
                .and_then(|r| {
                    r.email.as_ref().map(|address| {
                        if may_disclose {
                            address.clone()
                        } else {
                            crate::service::contact::ContactChannel::Email.mask(address)
                        }
                    })
                })
                .unwrap_or_default(),
            phone: row
                .as_ref()
                .and_then(|r| {
                    r.phone.as_ref().map(|address| {
                        if may_disclose {
                            address.clone()
                        } else {
                            crate::service::contact::ContactChannel::Phone.mask(address)
                        }
                    })
                })
                .unwrap_or_default(),
            status: row.as_ref().map(|r| r.status.clone()).unwrap_or_default(),
            reason: row
                .as_ref()
                .filter(|_| may_disclose)
                .map(|r| r.reason.clone())
                .unwrap_or_default(),
            social: social_only || row.as_ref().is_some_and(|r| r.provider_id.is_some()),
            tenant_name: String::new(),
            tenant_invitation: false,
            existing_account: existing.is_some(),
            signed_in: session.is_some(),
            matching_account,
            allowed_methods,
            providers,
            flow,
            can_act,
            can_resend: row
                .as_ref()
                .zip(progress.as_ref())
                .is_some_and(|(row, claim)| {
                    claim.id == row.id && row.allows_browser_resend(claim.verified)
                })
                && blocked.is_empty()
                && !contact_changed,
            already_admitted,
            error: if contact_changed {
                "enrollment_contact_changed"
            } else if !blocked.is_empty() {
                blocked
            } else {
                error
            }
            .to_owned(),
            expires_at: row.as_ref().and_then(|r| {
                r.expires_at
                    .format(&time::format_description::well_known::Rfc3339)
                    .ok()
            }),
        },
        jar,
    )
}

async fn registration_providers(
    state: &AppState,
    only: Option<Uuid>,
) -> Result<Vec<super::dto::SocialProvider>, sea_orm::DbErr> {
    let providers = crate::service::provider::enabled_social(&state.db).await?;
    Ok(providers
        .into_iter()
        .filter(|p| {
            only.is_none_or(|id| p.id == id)
                && p.settings
                    .get("allow_registration")
                    .and_then(|v| v.as_bool())
                    == Some(true)
        })
        .map(|p| super::dto::SocialProvider {
            key: p.code,
            name: p.name,
            icon: String::new(),
        })
        .collect())
}

async fn registration_session(
    state: &AppState,
    jar: &CookieJar,
) -> Result<Option<crate::state::session::SsoSession>, Box<Response>> {
    let Some(session) = crate::web::session::extract_browser_session(state, jar)
        .await
        .map_err(|status| Box::new(status.into_response()))?
    else {
        return Ok(None);
    };
    if session.recovery_pending || (session.mfa_required && session.mfa_verified_at.is_none()) {
        return Err(Box::new(
            Redirect::to("/sso/mfa?redirect=%2Fsso%2Fregister").into_response(),
        ));
    }
    crate::web::session::extract_session(state, jar)
        .await
        .map_err(|status| Box::new(status.into_response()))
}

async fn render_invitation(state: &AppState, jar: CookieJar, error: &str) -> Response {
    use crate::db::entity::users;
    let Some(token) = tenant_token(&jar) else {
        return Redirect::to("/sso/register").into_response();
    };
    let invite = match crate::service::tenant::invitation_progress(&state.db, token).await {
        Ok(v) => v,
        Err(crate::service::ManagementError::Invalid(_)) => {
            return render(state, clear_flow(jar), None, "invalid_invitation").await;
        }
        Err(e) => return util::management_response(Err(e)),
    };
    let policy = match enrollment::policy(&state.db, None).await {
        Ok(v) => v,
        Err(e) => return util::management_response(Err(e)),
    };
    let existing = match users::Entity::find()
        .filter(users::Column::Email.eq(invite.email.clone()))
        .filter(users::Column::DeletedAt.is_null())
        .one(&state.db)
        .await
    {
        Ok(v) => v,
        Err(e) => return util::dependency_error(e),
    };
    let session = match registration_session(state, &jar).await {
        Ok(v) => v,
        Err(e) => return *e,
    };
    let matching_account = session.as_ref().is_some_and(|s| {
        if invite.status == "accepted" {
            invite.accepted_user_id == Some(s.user_id)
        } else {
            existing.as_ref().is_some_and(|u| s.user_id == u.id)
        }
    });
    let already_admitted = if let Some(session) = session.as_ref().filter(|_| matching_account) {
        match crate::db::entity::tenant_members::Entity::find_by_id((
            invite.tenant_id,
            session.user_id,
        ))
        .one(&state.db)
        .await
        {
            Ok(member) => member.is_some_and(|m| m.status == "active"),
            Err(e) => return util::dependency_error(e),
        }
    } else {
        false
    };
    let social = social_proof(state, &jar).is_some_and(|p| {
        p.is_fresh()
            && p.invitation_hash.as_deref() == Some(pero_utils::crypto::sha256_hex(token).as_str())
    });
    let closed = policy.emergency_stop || (existing.is_none() && policy.mode == "closed");
    let providers =
        if invite.status == "pending" && !closed && existing.is_none() && session.is_none() {
            match registration_providers(state, None).await {
                Ok(v) => v,
                Err(e) => return util::dependency_error(e),
            }
        } else {
            vec![]
        };
    let flow = flow_binding(state, &jar);
    let (jar, csrf_token) = state.web_security().ensure_csrf(jar);
    let error = if invite.status == "blocked" {
        "tenant_disabled"
    } else {
        error
    };
    util::view_response(
        "EnrollmentView",
        View {
            csrf_token,
            mode: if closed {
                "closed".into()
            } else {
                "invite_only".into()
            },
            app: invite.app_id,
            email: invite.email,
            phone: String::new(),
            app_name: String::new(),
            status: match invite.status.as_str() {
                "pending" => "ready".into(),
                "accepted" => "completed".into(),
                _ => invite.status,
            },
            reason: String::new(),
            social,
            tenant_name: invite.tenant_name,
            tenant_invitation: true,
            existing_account: existing.is_some(),
            signed_in: session.is_some(),
            matching_account,
            allowed_methods: vec![],
            providers,
            flow,
            can_act: true,
            can_resend: false,
            already_admitted,
            error: error.to_owned(),
            expires_at: None,
        },
        jar,
    )
}

async fn cancel_registration(state: &AppState, jar: CookieJar, expired: bool) -> Response {
    use crate::db::entity::oauth_clients;
    use crate::db::enums::CommonStatus;
    let claim = progress_claim(state, &jar);
    let (client_id, request_id, tenant_id, completed) = if let Some(token) = tenant_token(&jar) {
        match crate::service::tenant::invitation_progress(&state.db, token).await {
            Ok(invite) => (
                invite.client_id,
                None,
                Some(invite.tenant_id),
                invite.status == "accepted",
            ),
            Err(e) => return util::management_response(Err(e)),
        }
    } else if flow_token(&jar).is_some() || claim.is_some() {
        let row = if let Some(claim) = claim {
            enrollment::progress(&state.db, claim.id).await
        } else {
            enrollment::progress_by_token(&state.db, flow_token(&jar).unwrap_or_default()).await
        };
        match row {
            Ok(row) => (
                row.client_id,
                row.auth_request_id,
                row.tenant_id,
                row.status == "completed",
            ),
            Err(crate::service::ManagementError::Invalid(_)) => (None, None, None, false),
            Err(e) => return util::management_response(Err(e)),
        }
    } else {
        match request_context(state, &jar) {
            Some(ctx) => (
                Some(ctx.client_id),
                Some(ctx.request_id),
                ctx.tenant_id,
                false,
            ),
            None => (None, None, None, false),
        }
    };
    let request = if request_id.is_some() && !expired {
        match active_request(state, &jar).await {
            Ok(request) => request.filter(|r| Some(r.id) == request_id),
            Err(error) => return util::management_response(Err(error)),
        }
    } else {
        None
    };
    let cookies = state.cookie_factory();
    let jar = clear_flow(jar);
    let jar = if request.is_some() {
        jar.add(cookies.clear_cookie(&cookies.nonce_cookie_name()))
            .add(cookies.clear_cookie(&cookies.auth_req_cookie_name()))
    } else {
        jar
    };
    if let Some(client_id) = client_id {
        let client = match oauth_clients::Entity::find_by_id(client_id)
            .one(&state.db)
            .await
        {
            Ok(v) => v.filter(|client| client.status == CommonStatus::Active),
            Err(e) => return util::dependency_error(e),
        };
        if let Some(client) = client {
            if let Some(request) = request.filter(|r| {
                !completed && r.client_id == client_id && r.diagnostic_session_id.is_none()
            }) && state
                .oauth_service()
                .validate_client(&client.identifier, &request.redirect_uri, &request.scopes)
                .await
                .is_ok()
            {
                let updated = authorization_requests::Entity::update_many()
                    .col_expr(
                        authorization_requests::Column::CompletedAt,
                        sea_orm::sea_query::Expr::value(Some(time::OffsetDateTime::now_utc())),
                    )
                    .filter(authorization_requests::Column::Id.eq(request.id))
                    .filter(authorization_requests::Column::CompletedAt.is_null())
                    .filter(
                        authorization_requests::Column::ExpiresAt
                            .gt(time::OffsetDateTime::now_utc()),
                    )
                    .exec(&state.db)
                    .await;
                match updated {
                    Ok(v) if v.rows_affected == 1 => {
                        let uri = pero_utils::oauth::url::build_error_redirect_url(
                            &request.redirect_uri,
                            "access_denied",
                            None,
                            request.client_state.as_deref(),
                        );
                        return (jar, Redirect::to(&uri)).into_response();
                    }
                    Ok(_) => {}
                    Err(e) => return util::dependency_error(e),
                }
            }
            let status = (!completed).then_some(if expired { "expired" } else { "cancelled" });
            match crate::web::login_flow::client_login_target(state, client, tenant_id, status)
                .await
            {
                Ok(Some(uri)) => return (jar, Redirect::to(&uri)).into_response(),
                Ok(None) => {}
                Err(e) => return util::dependency_error(e),
            }
        }
    }
    let target = if completed {
        tenant_id.map(|id| format!("/account/tenants/{id}"))
    } else {
        None
    }
    .unwrap_or_else(|| "/account/applications".to_owned());
    (jar, Redirect::to(&target)).into_response()
}

async fn continue_registration(state: &AppState, jar: CookieJar) -> Response {
    use crate::service::ManagementError;

    let session = match registration_session(state, &jar).await {
        Ok(Some(session)) => session,
        Ok(None) => {
            return util::management_response(Err(ManagementError::Invalid(
                "existing_account_login_required",
            )));
        }
        Err(response) => return *response,
    };
    let result = if let Some(token) = tenant_token(&jar) {
        crate::service::tenant::invitation_progress(&state.db, token)
            .await
            .map(|invite| {
                (invite.status == "accepted" && invite.accepted_user_id == Some(session.user_id))
                    .then_some(enrollment::EnrollmentResult {
                        user_id: session.user_id,
                        identity: None,
                        app_id: invite.app_id,
                        client_id: invite.client_id,
                        auth_request_id: None,
                        resume_portal: false,
                        tenant_id: Some(invite.tenant_id),
                    })
            })
    } else {
        let row = if let Some(claim) = progress_claim(state, &jar) {
            enrollment::progress(&state.db, claim.id).await
        } else {
            enrollment::progress_by_token(&state.db, flow_token(&jar).unwrap_or_default()).await
        };
        row.map(|row| row.completed_result(&session))
    };
    match result {
        Ok(Some(result)) => {
            crate::web::login_flow::finish_enrollment(state, jar, result, None, None).await
        }
        Ok(None) => {
            util::management_response(Err(ManagementError::Invalid("enrollment_unavailable")))
        }
        Err(error) => util::management_response(Err(error)),
    }
}

pub async fn post(
    State(state): State<AppState>,
    jar: CookieJar,
    pero_api_axum::extractor::ClientIp(ip): pero_api_axum::extractor::ClientIp,
    headers: axum::http::HeaderMap,
    Form(input): Form<Input>,
) -> Response {
    if let Some(e) = util::verify_csrf_or_json_error(&jar, &input.csrf_token, &state) {
        return e;
    }
    if !flow_matches(&state, &jar, Some(&input.flow)) {
        return util::management_response(Err(crate::service::ManagementError::Invalid(
            "enrollment_flow_changed",
        )));
    }
    match input.action.as_str() {
        "reset" => return cancel_registration(&state, jar, false).await,
        "continue" => return continue_registration(&state, jar).await,
        _ => {}
    }
    let source_ip = ip;
    let ip = pero_api_axum::extractor::ClientIp(ip).for_rate_limit();
    let key = match pero_cache_redis::rate_limit_key::rl_register_ip.key(&ip) {
        Ok(k) => k,
        Err(e) => return util::dependency_error(e),
    };
    if let Err(e) = pero_cache_redis::enforce_rate_limit(&state.cache, &key, 10).await {
        return match e {
            pero_cache_redis::RateLimitError::Denied { .. } => (
                axum::http::StatusCode::TOO_MANY_REQUESTS,
                pero_api_axum::json_error("rate_limited"),
            )
                .into_response(),
            _ => util::dependency_error(e),
        };
    }
    if matches!(input.action.as_str(), "switch" | "sign_out") {
        let jar = match crate::web::oauth2::select_account::switch(&state, jar).await {
            Ok(jar) => jar.remove(Cookie::build(SOCIAL_COOKIE).path("/sso").build()),
            Err(e) => return *e,
        };
        let target = if input.action == "switch" {
            format!(
                "{LOGIN_PATH}?redirect=%2Fsso%2Fregister&flow={}",
                flow_binding(&state, &jar)
            )
        } else {
            "/sso/register".to_owned()
        };
        return (jar, Redirect::to(&target)).into_response();
    }
    if let Some(token) = tenant_token(&jar) {
        match input.action.as_str() {
            "finalize" => {
                let session = match registration_session(&state, &jar).await {
                    Ok(session) => session,
                    Err(response) => return *response,
                };
                let proof = social_proof(&state, &jar);
                return match crate::service::tenant::finalize_invitation(
                    &state,
                    token,
                    &input.username,
                    &input.password,
                    session.as_ref(),
                    proof.as_ref(),
                )
                .await
                {
                    Ok(result) => {
                        crate::web::login_flow::finish_enrollment(
                            &state,
                            jar,
                            result,
                            source_ip,
                            util::user_agent(&headers),
                        )
                        .await
                    }
                    Err(crate::service::ManagementError::Invalid("reauth_required")) => (
                        jar,
                        Redirect::to("/account/reauth?redirect=%2Fsso%2Fregister"),
                    )
                        .into_response(),
                    Err(crate::service::ManagementError::Invalid("invalid_invitation")) => {
                        render_invitation(&state, jar, "invalid_invitation").await
                    }
                    Err(e) => util::management_response(Err(e)),
                };
            }
            _ => {
                return util::management_response(Err(crate::service::ManagementError::Invalid(
                    "invalid_request",
                )));
            }
        }
    }
    let request = match registration_request(&state, &jar).await {
        Ok(request) => request,
        Err(e) => return util::management_response(Err(e)),
    };
    if request.is_none()
        && flow_token(&jar).is_none()
        && progress_claim(&state, &jar).is_none()
        && request_context_client(&state, &jar).is_some()
    {
        return cancel_registration(&state, jar, true).await;
    }
    let app = request.as_ref().map(|r| r.app_id);
    if input.action == "use_account"
        && let Some(request) = &request
        && !has_registration(&state, &jar)
    {
        return match crate::web::login_flow::enrollment_resume_target(&state, request, None, None) {
            Ok(uri) => (clear_flow(jar), Redirect::to(&uri)).into_response(),
            Err(error) => util::dependency_error(error),
        };
    }
    if input.action.is_empty() && input.app != app {
        return util::management_response(Err(crate::service::ManagementError::Invalid(
            "enrollment_unavailable",
        )));
    }
    let claim = progress_claim(&state, &jar);
    if input.action == "resend" {
        return match claim {
            Some(claim) => match enrollment::resend(&state, claim.id, claim.verified).await {
                Ok(()) => render(&state, jar, app, "").await,
                Err(e) => util::management_response(Err(e)),
            },
            None => util::management_response(Err(crate::service::ManagementError::Invalid(
                "enrollment_unavailable",
            ))),
        };
    }
    match input.action.as_str() {
        "verify" => {
            let Some(token) = flow_token(&jar) else {
                return util::management_response(Err(crate::service::ManagementError::Invalid(
                    "enrollment_unavailable",
                )));
            };
            match enrollment::verify(&state, token).await {
                Ok(id) => match with_progress(&state, jar, id, true) {
                    Ok(jar) => render(&state, jar, app, "").await,
                    Err(error) => util::management_response(Err(error)),
                },
                Err(crate::service::ManagementError::Invalid("enrollment_unavailable")) => {
                    render(&state, jar, app, "").await
                }
                Err(error) => util::management_response(Err(error)),
            }
        }
        "finalize" => {
            let Some(token) = flow_token(&jar) else {
                return render(&state, jar, app, "").await;
            };
            let session = match registration_session(&state, &jar).await {
                Ok(session) => session,
                Err(response) => return *response,
            };
            let proof = social_proof(&state, &jar);
            match enrollment::finalize(
                &state,
                token,
                &input.username,
                &input.password,
                session.as_ref(),
                proof.as_ref(),
            )
            .await
            {
                Ok(result) => {
                    crate::web::login_flow::finish_enrollment(
                        &state,
                        jar,
                        result,
                        source_ip,
                        util::user_agent(&headers),
                    )
                    .await
                }
                Err(crate::service::ManagementError::Invalid("enrollment_unavailable")) => {
                    render(&state, jar, app, "").await
                }
                Err(error) => util::management_response(Err(error)),
            }
        }
        "" if flow_token(&jar).is_none() => {
            let proof = social_proof(&state, &jar);
            let previous = claim.as_ref().map(|claim| claim.id);
            let id = if let Some(proof) = &proof {
                if !proof.is_fresh() || proof.invitation_hash.is_some() || proof.app != app {
                    return util::management_response(Err(
                        crate::service::ManagementError::Invalid(
                            "social_reauthentication_required",
                        ),
                    ));
                }
                enrollment::start_social(
                    &state,
                    &input.email,
                    proof.provider,
                    &proof.subject,
                    request.as_ref(),
                    previous,
                )
                .await
            } else {
                let is_phone = !input.phone.trim().is_empty();
                enrollment::start_from_request(
                    &state,
                    if is_phone { &input.phone } else { &input.email },
                    is_phone,
                    request.as_ref(),
                    previous,
                )
                .await
            };
            let id = match id {
                Ok(id) => id,
                Err(e) => return util::management_response(Err(e)),
            };
            let jar = if let Some(mut proof) = proof {
                proof.enrollment_id = Some(id);
                match with_social_proof(&state, jar, &proof) {
                    Ok(jar) => jar,
                    Err(e) => return util::management_response(Err(e)),
                }
            } else {
                jar
            };
            let jar = match with_progress(&state, jar, id, false) {
                Ok(jar) => jar,
                Err(e) => return util::management_response(Err(e)),
            };
            render(&state, jar, app, "").await
        }
        _ => util::management_response(Err(crate::service::ManagementError::Invalid(
            "invalid_request",
        ))),
    }
}

pub async fn social(
    state: &AppState,
    jar: CookieJar,
    provider: Uuid,
    info: crate::service::social::SocialUserInfo,
    request: Option<&authorization_requests::Model>,
) -> Response {
    if let Err(e) = enrollment::allow_social(&state.db, provider).await {
        return util::management_response(Err(e));
    }
    let app = request.map(|request| request.app_id);
    let invitation_hash = tenant_token(&jar).map(pero_utils::crypto::sha256_hex);
    let mut proof = SocialProof {
        invitation_hash,
        provider,
        subject: info.sub.clone(),
        proved_at: time::OffsetDateTime::now_utc().unix_timestamp(),
        app,
        enrollment_id: None,
    };
    let mut pending_id = None;
    if let Some(token) = tenant_token(&jar) {
        if let Err(e) = crate::service::tenant::invitation(&state.db, token).await {
            return util::management_response(Err(e));
        }
    } else if let Some(token) = flow_token(&jar) {
        let row = match enrollment::lookup(&state.db, token).await {
            Ok(row) => row,
            Err(e) => return util::management_response(Err(e)),
        };
        if row.provider_id != Some(provider) || row.subject.as_deref() != Some(&info.sub) {
            return (
                jar,
                Redirect::to("/sso/register?error=social_reauthentication_required"),
            )
                .into_response();
        }
        proof.app = row.app_id;
        proof.enrollment_id = Some(row.id);
    } else if progress_claim(state, &jar).is_some() {
        return (
            jar,
            Redirect::to("/sso/register?error=enrollment_unavailable"),
        )
            .into_response();
    } else if let Some(address) = info.email.as_deref() {
        match enrollment::start_social(state, address, provider, &info.sub, request, None).await {
            Ok(id) => {
                pending_id = Some(id);
                proof.enrollment_id = Some(id);
            }
            Err(crate::service::ManagementError::Invalid(code)) => {
                let mut target = "/sso/register".to_owned();
                pero_utils::encode::append_query_param(&mut target, "error", code);
                return (jar, Redirect::to(&target)).into_response();
            }
            Err(e) => return util::management_response(Err(e)),
        }
    }
    let jar = match with_social_proof(state, jar, &proof) {
        Ok(jar) => jar,
        Err(e) => return util::management_response(Err(e)),
    };
    let jar = match pending_id {
        Some(id) => match with_progress(state, jar, id, false) {
            Ok(jar) => jar,
            Err(e) => return util::management_response(Err(e)),
        },
        None => jar,
    };
    (jar, Redirect::to("/sso/register")).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registration_cookies_are_cleared_outside_the_sso_path() {
        let jar = clear_flow(CookieJar::new());
        assert!(flow_token(&jar).is_none());
        assert!(tenant_token(&jar).is_none());
        let response = (jar, axum::http::StatusCode::NO_CONTENT).into_response();
        let headers = response.headers().get_all(axum::http::header::SET_COOKIE);
        for name in [
            FLOW_COOKIE,
            SOCIAL_COOKIE,
            INVITATION_COOKIE,
            REQUEST_CONTEXT_COOKIE,
            PROGRESS_COOKIE,
        ] {
            assert!(headers.iter().any(|header| {
                let value = header.to_str().unwrap();
                value.starts_with(&format!("{name}="))
                    && value.contains("Path=/sso")
                    && value.contains("Max-Age=0")
            }));
        }
    }
}
