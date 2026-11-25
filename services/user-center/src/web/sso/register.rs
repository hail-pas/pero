use crate::db::entity::authorization_requests;
use crate::{service::enrollment, state::app::AppState, web::util};
use axum::{
    Form,
    extract::{Query, State},
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::{CookieJar, cookie::Cookie};
use enrollment::SocialProof;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, TransactionTrait};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
const SOCIAL_COOKIE: &str = "pero_enrollment_identity";
const FLOW_COOKIE: &str = "pero_enrollment";
const INVITATION_COOKIE: &str = "pero_tenant_invitation";
#[derive(Default, Deserialize)]
pub struct Params {
    pub token: Option<String>,
    pub invitation: Option<String>,
    pub app: Option<Uuid>,
    #[serde(default)]
    pub sent: bool,
}
#[derive(Default, Deserialize)]
pub struct Input {
    #[serde(default)]
    pub csrf_token: String,
    #[serde(default)]
    pub action: String,
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
    sent: bool,
    tenant_name: String,
    tenant_invitation: bool,
    existing_account: bool,
    signed_in: bool,
    matching_account: bool,
    allowed_methods: Vec<&'static str>,
    providers: Vec<super::dto::SocialProvider>,
}
pub(crate) fn clear_flow(jar: CookieJar) -> CookieJar {
    jar.remove(Cookie::build(FLOW_COOKIE).path("/sso").build())
        .remove(Cookie::build(SOCIAL_COOKIE).path("/sso").build())
        .remove(Cookie::build(INVITATION_COOKIE).path("/sso").build())
}

async fn active_request(
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
    jar.get(INVITATION_COOKIE).map(|c| c.value())
}

pub fn flow_token(jar: &CookieJar) -> Option<&str> {
    jar.get(FLOW_COOKIE).map(|c| c.value())
}
pub(crate) fn flow_cookie(state: &AppState, token: String) -> Cookie<'static> {
    Cookie::build((FLOW_COOKIE, token))
        .path("/sso")
        .http_only(true)
        .secure(state.config.sso.cookie_secure)
        .same_site(axum_extra::extract::cookie::SameSite::Lax)
        .max_age(time::Duration::days(7))
        .build()
}
fn social_proof(state: &AppState, jar: &CookieJar) -> Option<SocialProof> {
    jar.get(SOCIAL_COOKIE).and_then(|c| {
        pero_utils::crypto::decode_signed_json(
            c.value(),
            state
                .config
                .sso
                .cookie_signing_secret
                .expose_secret()
                .as_bytes(),
        )
        .ok()
    })
}

pub async fn get(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(query): Query<Params>,
) -> Response {
    if let Some(token) = query.invitation {
        if let Err(e) = crate::service::tenant::invitation_progress(&state.db, &token).await {
            return util::management_response(Err(e));
        }
        let cookies = state.cookie_factory();
        let jar = clear_flow(jar)
            .add(cookies.clear_cookie(&cookies.nonce_cookie_name()))
            .add(cookies.clear_cookie(&cookies.auth_req_cookie_name()));
        let cookie = Cookie::build((INVITATION_COOKIE, token))
            .path("/sso")
            .http_only(true)
            .secure(state.config.sso.cookie_secure)
            .same_site(axum_extra::extract::cookie::SameSite::Lax)
            .max_age(time::Duration::days(7))
            .build();
        return (jar.add(cookie), Redirect::to("/sso/register")).into_response();
    }
    if let Some(token) = query.token {
        let row = match enrollment::progress_by_token(&state.db, &token).await {
            Ok(row) => row,
            Err(e) => return util::management_response(Err(e)),
        };
        let proof_cookie = jar
            .get(SOCIAL_COOKIE)
            .cloned()
            .filter(|_| social_proof(&state, &jar).is_some_and(|proof| proof.matches(&row)));
        let request = match active_request(&state, &jar).await {
            Ok(request) => request,
            Err(e) => return util::management_response(Err(e)),
        };
        let cookies = state.cookie_factory();
        let mut jar = clear_flow(jar).add(flow_cookie(&state, token));
        if request
            .as_ref()
            .is_some_and(|r| Some(r.id) != row.auth_request_id)
        {
            jar = jar
                .add(cookies.clear_cookie(&cookies.nonce_cookie_name()))
                .add(cookies.clear_cookie(&cookies.auth_req_cookie_name()));
        }
        if let Some(cookie) = proof_cookie {
            jar = jar.add(cookie);
        }
        return (jar, Redirect::to("/sso/register")).into_response();
    }
    if tenant_token(&jar).is_some() {
        return render_invitation(&state, jar).await;
    }
    let request = match active_request(&state, &jar).await {
        Ok(request) => request,
        Err(e) => return util::management_response(Err(e)),
    };
    let app = request.as_ref().map(|r| r.app_id).or(query.app);
    let jar = if let (Some(request), Some(token)) = (&request, flow_token(&jar)) {
        match enrollment::progress_by_token(&state.db, token).await {
            Ok(row) if row.auth_request_id != Some(request.id) => clear_flow(jar),
            _ => jar,
        }
    } else {
        jar
    };
    render(&state, jar, app, query.sent).await
}
async fn render(state: &AppState, jar: CookieJar, app: Option<Uuid>, sent: bool) -> Response {
    let row = if let Some(token) = flow_token(&jar) {
        match enrollment::progress_by_token(&state.db, token).await {
            Ok(r) => Some(r),
            Err(crate::service::ManagementError::Invalid(_)) => None,
            Err(e) => return util::management_response(Err(e)),
        }
    } else {
        None
    };
    let app = row.as_ref().map(|r| r.app_id).unwrap_or(app);
    let terminal = row.as_ref().is_some_and(|r| {
        matches!(
            r.status.as_str(),
            "completed" | "rejected" | "revoked" | "expired"
        )
    });
    let p = match enrollment::policy(&state.db, if terminal { None } else { app }).await {
        Ok(p) => p,
        Err(e) => return util::management_response(Err(e)),
    };
    let mut organization_only = false;
    let app_name = if let Some(id) = app {
        use sea_orm::EntityTrait;
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
    let social_only = row.as_ref().is_none() && proof.as_ref().is_some_and(|p| p.is_fresh());
    let mut allowed_methods = Vec::new();
    if state.config.notification.available("email") {
        allowed_methods.push("email");
    }
    if !social_only && p.domains.is_empty() && state.config.notification.available("phone") {
        allowed_methods.push("phone");
    }
    let providers = match registration_providers(state).await {
        Ok(v) => v,
        Err(e) => return e,
    };
    let session = match crate::web::session::extract_session(state, &jar).await {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    let existing = if let Some(row) = row.as_ref().filter(|row| row.status == "ready") {
        use crate::db::entity::users;
        let contact = if let Some(email) = &row.email {
            users::Column::Email.eq(email.clone())
        } else if let Some(phone) = &row.phone {
            users::Column::Phone.eq(phone.clone())
        } else {
            return util::management_response(Err(crate::service::ManagementError::Invalid(
                "enrollment_unavailable",
            )));
        };
        match users::Entity::find().filter(contact).one(&state.db).await {
            Ok(v) => v,
            Err(e) => return util::dependency_error(e),
        }
    } else {
        None
    };
    let matching_account = existing
        .as_ref()
        .is_some_and(|user| session.as_ref().is_some_and(|s| s.user_id == user.id));
    let (jar, csrf_token) = state.web_security().ensure_csrf(jar);
    util::view_response(
        "EnrollmentView",
        View {
            csrf_token,
            app,
            mode: if p.emergency_stop {
                "closed".into()
            } else if organization_only && row.is_none() {
                "invite_only".into()
            } else {
                p.mode
            },
            app_name,
            email: row
                .as_ref()
                .and_then(|r| r.email.clone())
                .unwrap_or_default(),
            phone: row
                .as_ref()
                .and_then(|r| r.phone.clone())
                .unwrap_or_default(),
            status: row.as_ref().map(|r| r.status.clone()).unwrap_or_default(),
            reason: row.as_ref().map(|r| r.reason.clone()).unwrap_or_default(),
            social: social_only || row.as_ref().is_some_and(|r| r.provider_id.is_some()),
            sent,
            tenant_name: String::new(),
            tenant_invitation: false,
            existing_account: existing.is_some(),
            signed_in: session.is_some(),
            matching_account,
            allowed_methods,
            providers,
        },
        jar,
    )
}

async fn registration_providers(
    state: &AppState,
) -> Result<Vec<super::dto::SocialProvider>, Response> {
    let providers = crate::service::provider::enabled_social(&state.db)
        .await
        .map_err(util::dependency_error)?;
    Ok(providers
        .into_iter()
        .filter(|p| {
            p.settings
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

async fn render_invitation(state: &AppState, jar: CookieJar) -> Response {
    use crate::db::entity::users;
    use sea_orm::{ColumnTrait, QueryFilter};
    let Some(token) = tenant_token(&jar) else {
        return Redirect::to("/sso/register").into_response();
    };
    let invite = match crate::service::tenant::invitation_progress(&state.db, token).await {
        Ok(v) => v,
        Err(e) => return util::management_response(Err(e)),
    };
    let policy = match enrollment::policy(&state.db, None).await {
        Ok(v) => v,
        Err(e) => return util::management_response(Err(e)),
    };
    let existing = match users::Entity::find()
        .filter(users::Column::Email.eq(invite.email.clone()))
        .one(&state.db)
        .await
    {
        Ok(v) => v,
        Err(e) => return util::dependency_error(e),
    };
    let session = match crate::web::session::extract_session(state, &jar).await {
        Ok(v) => v,
        Err(e) => return e.into_response(),
    };
    let matching_account = existing
        .as_ref()
        .is_some_and(|u| session.as_ref().is_some_and(|s| s.user_id == u.id));
    let social = social_proof(state, &jar).is_some_and(|p| {
        p.is_fresh()
            && p.invitation_hash.as_deref() == Some(pero_utils::crypto::sha256_hex(token).as_str())
    });
    let providers = match registration_providers(state).await {
        Ok(v) => v,
        Err(e) => return e,
    };
    let (jar, csrf_token) = state.web_security().ensure_csrf(jar);
    util::view_response(
        "EnrollmentView",
        View {
            csrf_token,
            mode: if policy.emergency_stop || (existing.is_none() && policy.mode == "closed") {
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
            sent: false,
            tenant_name: invite.tenant_name,
            tenant_invitation: true,
            existing_account: existing.is_some(),
            signed_in: session.is_some(),
            matching_account,
            allowed_methods: vec![],
            providers,
        },
        jar,
    )
}

async fn cancel_registration(state: &AppState, jar: CookieJar) -> Response {
    use crate::db::entity::oauth_clients;
    use crate::db::enums::CommonStatus;
    let request = match active_request(state, &jar).await {
        Ok(v) => v,
        Err(e) => return util::management_response(Err(e)),
    };
    let (client_id, request_id, tenant_id) = if let Some(token) = tenant_token(&jar) {
        match crate::service::tenant::invitation_progress(&state.db, token).await {
            Ok(invite) => (invite.client_id, None, Some(invite.tenant_id)),
            Err(e) => return util::management_response(Err(e)),
        }
    } else if let Some(token) = flow_token(&jar) {
        match enrollment::progress_by_token(&state.db, token).await {
            Ok(row) => (row.client_id, row.auth_request_id, None),
            Err(e) => return util::management_response(Err(e)),
        }
    } else {
        (
            request.as_ref().map(|r| r.client_id),
            request.as_ref().map(|r| r.id),
            None,
        )
    };
    let cookies = state.cookie_factory();
    let jar = clear_flow(jar)
        .add(cookies.clear_cookie(&cookies.nonce_cookie_name()))
        .add(cookies.clear_cookie(&cookies.auth_req_cookie_name()));
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
                Some(r.id) == request_id
                    && r.client_id == client_id
                    && r.diagnostic_session_id.is_none()
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
                        let mut uri = request.redirect_uri;
                        pero_utils::encode::append_query_param(&mut uri, "error", "access_denied");
                        if let Some(state) = request.client_state {
                            pero_utils::encode::append_query_param(&mut uri, "state", &state);
                        }
                        return (jar, Redirect::to(&uri)).into_response();
                    }
                    Ok(_) => {}
                    Err(e) => return util::dependency_error(e),
                }
            }
            if let Some(mut uri) = client.login_uri {
                pero_utils::encode::append_query_param(&mut uri, "enrollment_status", "cancelled");
                if let Some(tenant) = tenant_id {
                    pero_utils::encode::append_query_param(
                        &mut uri,
                        "tenant_id",
                        &tenant.to_string(),
                    );
                }
                return (jar, Redirect::to(&uri)).into_response();
            }
        }
    }
    (jar, Redirect::to("/account/applications")).into_response()
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
    if input.action == "switch" {
        let session = match crate::web::session::extract_browser_session(&state, &jar).await {
            Ok(v) => v,
            Err(e) => return e.into_response(),
        };
        if let Some(session) = session {
            if let Err(e) = state
                .session_service()
                .revoke_login_state(session.id, "account_switch")
                .await
            {
                return util::dependency_error(e);
            }
        }
        let cookies = state.cookie_factory();
        let jar = jar
            .add(cookies.clear_cookie(cookies.session_cookie_name()))
            .remove(Cookie::build(SOCIAL_COOKIE).path("/sso").build());
        return (
            jar,
            Redirect::to("/account/login?redirect=%2Fsso%2Fregister"),
        )
            .into_response();
    }
    if input.action == "reset" {
        return cancel_registration(&state, jar).await;
    }
    if let Some(token) = tenant_token(&jar) {
        let session = match crate::web::session::extract_session(&state, &jar).await {
            Ok(v) => v,
            Err(e) => return e.into_response(),
        };
        match input.action.as_str() {
            "finalize" => {
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
                            clear_flow(jar),
                            result,
                            None,
                            source_ip,
                            util::user_agent(&headers),
                        )
                        .await
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
    let request = match active_request(&state, &jar).await {
        Ok(request) => request,
        Err(e) => return util::management_response(Err(e)),
    };
    let result = match input.action.as_str() {
        "verify" => match flow_token(&jar) {
            Some(token) => enrollment::verify(&state, token).await,
            None => Err(crate::service::ManagementError::Invalid(
                "enrollment_unavailable",
            )),
        },
        "finalize" => {
            let session = match crate::web::session::extract_session(&state, &jar).await {
                Ok(s) => s,
                Err(e) => return e.into_response(),
            };
            let proof = social_proof(&state, &jar);
            match flow_token(&jar) {
                Some(token) => {
                    return match enrollment::finalize(
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
                                clear_flow(jar),
                                result,
                                request.as_ref(),
                                source_ip,
                                util::user_agent(&headers),
                            )
                            .await
                        }
                        Err(e) => util::management_response(Err(e)),
                    };
                }
                None => Err(crate::service::ManagementError::Invalid(
                    "enrollment_unavailable",
                )),
            }
        }
        "" => {
            let proof = social_proof(&state, &jar);
            if let Some(proof) = proof {
                if !proof.is_fresh() {
                    return util::management_response(Err(
                        crate::service::ManagementError::Invalid(
                            "social_reauthentication_required",
                        ),
                    ));
                }
                let address = match enrollment::email(&input.email) {
                    Ok(v) => v,
                    Err(e) => return util::management_response(Err(e)),
                };
                enrollment::start_social(
                    &state,
                    &address,
                    proof.app,
                    proof.provider,
                    &proof.subject,
                    request.as_ref(),
                )
                .await
            } else {
                let app = request.as_ref().map(|r| r.app_id).or(input.app);
                let is_phone = !input.phone.trim().is_empty();
                enrollment::start_from_request(
                    &state,
                    if is_phone { &input.phone } else { &input.email },
                    is_phone,
                    app,
                    request.as_ref(),
                )
                .await
            }
        }
        _ => Err(crate::service::ManagementError::Invalid("invalid_request")),
    };
    match result {
        Err(e) => util::management_response(Err(e)),
        Ok(()) => render(&state, jar, input.app, input.action.is_empty()).await,
    }
}

pub async fn social(
    state: &AppState,
    jar: CookieJar,
    provider: Uuid,
    info: crate::service::social::SocialUserInfo,
    app: Option<Uuid>,
    redirect: &str,
) -> Response {
    if let Err(e) = enrollment::allow_social(&state.db, provider).await {
        return util::management_response(Err(e));
    }
    let invitation_hash = tenant_token(&jar).map(pero_utils::crypto::sha256_hex);
    let flow_hash = flow_token(&jar).map(pero_utils::crypto::sha256_hex);
    if (redirect.starts_with("/sso/register?invitation_flow=") && invitation_hash.is_none())
        || (redirect.starts_with("/sso/register?enrollment_flow=") && flow_hash.is_none())
        || flow_hash
            .as_ref()
            .is_some_and(|hash| redirect != format!("/sso/register?enrollment_flow={hash}"))
    {
        return util::management_response(Err(crate::service::ManagementError::Invalid(
            "enrollment_unavailable",
        )));
    }
    let app = if let Some(token) = flow_token(&jar) {
        match enrollment::lookup(&state.db, token).await {
            Ok(row) => row.app_id,
            Err(e) => return util::management_response(Err(e)),
        }
    } else {
        app
    };
    if let Some(hash) = invitation_hash.as_deref() {
        if redirect != format!("/sso/register?invitation_flow={hash}") {
            return util::management_response(Err(crate::service::ManagementError::Invalid(
                "invalid_invitation",
            )));
        }
        let token = tenant_token(&jar).unwrap_or_default();
        if let Err(e) = crate::service::tenant::invitation(&state.db, token).await {
            return util::management_response(Err(e));
        }
    }
    let proof = SocialProof {
        invitation_hash,
        provider,
        subject: info.sub.clone(),
        proved_at: time::OffsetDateTime::now_utc().unix_timestamp(),
        app,
    };
    let value = match pero_utils::crypto::encode_signed_json(
        &proof,
        state
            .config
            .sso
            .cookie_signing_secret
            .expose_secret()
            .as_bytes(),
    ) {
        Ok(v) => v,
        Err(e) => return util::dependency_error(e),
    };
    let cookie = Cookie::build((SOCIAL_COOKIE, value))
        .path("/sso")
        .http_only(true)
        .secure(state.config.sso.cookie_secure)
        .same_site(axum_extra::extract::cookie::SameSite::Lax)
        .max_age(time::Duration::minutes(10))
        .build();
    let jar = jar.add(cookie);
    if tenant_token(&jar).is_some() {
        return (jar, Redirect::to("/sso/register")).into_response();
    }
    if let Some(token) = flow_token(&jar) {
        let result = async {
            let txn = state.db.begin().await?;
            crate::service::admin::lock_policy(&txn).await?;
            let row = enrollment::lookup(&txn, token).await?;
            if row.provider_id.is_some()
                && (row.provider_id != Some(provider) || row.subject.as_deref() != Some(&info.sub))
            {
                return Err(crate::service::ManagementError::Invalid(
                    "enrollment_unavailable",
                ));
            }
            if let Some(address) = info.email.as_deref()
                && Some(enrollment::email(address)?) != row.email
            {
                return Err(crate::service::ManagementError::Invalid("invalid_email"));
            }
            crate::service::security::execute(
                &txn,
                "UPDATE enrollments SET provider_id=$2,subject=$3 WHERE id=$1",
                vec![row.id.into(), provider.into(), info.sub.into()],
            )
            .await?;
            txn.commit().await?;
            Ok(())
        }
        .await;
        return match result {
            Ok(()) => (jar, Redirect::to("/sso/register")).into_response(),
            Err(e) => util::management_response(Err(e)),
        };
    }
    if let Some(address) = info.email.as_deref() {
        let result = async {
            let address = enrollment::email(address)?;
            let request = active_request(state, &jar).await?;
            enrollment::start_social(state, &address, app, provider, &info.sub, request.as_ref())
                .await
        }
        .await;
        return match result {
            Ok(()) => (jar, Redirect::to("/sso/register?sent=true")).into_response(),
            Err(e) => util::management_response(Err(e)),
        };
    }
    let target = app
        .map(|a| format!("/sso/register?app={a}"))
        .unwrap_or_else(|| "/sso/register".into());
    (jar, Redirect::to(&target)).into_response()
}
