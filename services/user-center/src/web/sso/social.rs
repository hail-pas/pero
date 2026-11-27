use axum::Form;
use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::cookie::CookieJar;
use pero_api_axum::extractor::ClientIp;
use sea_orm::EntityTrait;
use uuid::Uuid;

use crate::db::enums::UserStatus;
use crate::service::login::LoginService;
use crate::service::social::{IdentityResolution, LoginPurpose, SocialLinkError, SocialLoginError};
use crate::state::app::AppState;
use crate::web::login_flow::{LoginFormError, verify_password_for_user};
use crate::web::security::SOCIAL_LINK_COOKIE;
use crate::web::sso::dto::{SocialLinkForm, SocialLinkView};

#[derive(serde::Deserialize)]
pub struct LoginQuery {
    #[serde(default)]
    pub redirect: String,
    #[serde(default)]
    pub existing: bool,
    pub flow: Option<String>,
}

fn registration_target(redirect: &str) -> (&str, bool) {
    redirect
        .strip_suffix("?existing=1")
        .or_else(|| redirect.strip_suffix("&existing=1"))
        .filter(|target| *target == "/sso/register" || target.starts_with("/sso/register?"))
        .map_or((redirect, false), |target| (target, true))
}

pub async fn login(
    State(state): State<AppState>,
    jar: CookieJar,
    source: ClientIp,
    Path(provider_code): Path<String>,
    Query(query): Query<LoginQuery>,
) -> Response {
    let redirect = pero_utils::redirect::safe_site_redirect(&query.redirect, "/account/profile");
    let registration = redirect.split('?').next() == Some("/sso/register");
    if registration && !super::register::flow_matches(&state, &jar, query.flow.as_deref()) {
        return social_error(jar, true, "enrollment_flow_changed");
    }
    if let Err(status) = crate::web::login_flow::check_login_start_rate_limit(&state, source).await
    {
        if registration {
            let code = if status == axum::http::StatusCode::TOO_MANY_REQUESTS {
                "rate_limited"
            } else {
                "service_unavailable"
            };
            return social_error(jar, true, code);
        }
        return status.into_response();
    }
    let svc = state.social_service();

    let provider = match svc.find_provider_by_code(&provider_code).await {
        Ok(p) => p,
        Err(_) => return social_error(jar, registration, "unknown_provider"),
    };

    let auth_request_id = if registration && !super::register::has_registration(&state, &jar) {
        match super::register::registration_request(&state, &jar).await {
            Ok(Some(request)) => Some(request.id),
            Ok(None) if super::register::request_context_client(&state, &jar).is_some() => {
                return Redirect::to("/sso/register").into_response();
            }
            Ok(None) => None,
            Err(error) => return super::register::social_failure(jar, error),
        }
    } else if query.redirect.is_empty() {
        match super::register::active_request(&state, &jar).await {
            Ok(request) => request.map(|request| request.id),
            Err(error) => {
                tracing::error!(%error, "Pending authorization lookup failed");
                return axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response();
            }
        }
    } else {
        None
    };
    let mut redirect = redirect;
    if registration {
        redirect = "/sso/register".to_owned();
        pero_utils::encode::append_query_param(
            &mut redirect,
            "flow",
            query.flow.as_deref().unwrap_or_default(),
        );
        if query.existing {
            pero_utils::encode::append_query_param(&mut redirect, "existing", "1");
        }
    }
    let prepared = match svc
        .prepare_login_state(&provider, &provider_code, auth_request_id, &redirect, None)
        .await
    {
        Ok(p) => p,
        Err(SocialLoginError::ProviderMisconfigured) => {
            return social_error(jar, registration, "provider_misconfigured");
        }
        Err(_) => return social_error(jar, registration, "internal_error"),
    };

    let cookies = state.cookie_factory();
    let social_state_cookie = cookies.build_short_lived_cookie(
        &cookies.social_state_cookie_name(),
        &prepared.state_hash,
        state.config.oauth2.authorization_request_ttl_seconds,
    );

    (
        jar.add(social_state_cookie),
        Redirect::to(&prepared.authorize_url),
    )
        .into_response()
}

pub async fn callback(
    State(state): State<AppState>,
    jar: CookieJar,
    ClientIp(ip): ClientIp,
    Path(provider_code): Path<String>,
    headers: axum::http::HeaderMap,
    Query(params): Query<CallbackParams>,
) -> Response {
    let state_token = match &params.state {
        Some(s) => s.clone(),
        None => return Redirect::to("/sso/error?code=invalid_state").into_response(),
    };

    let state_hash = pero_utils::crypto::sha256_hex(&state_token);

    let cookies = state.cookie_factory();
    let ss_cookie_name = cookies.social_state_cookie_name();
    let cookie_hash = jar.get(&ss_cookie_name).map(|c| c.value().to_owned());
    match cookie_hash {
        Some(h) if pero_utils::crypto::constant_time_eq(h.as_bytes(), state_hash.as_bytes()) => {}
        _ => return Redirect::to("/sso/error?code=invalid_state").into_response(),
    }
    let jar = jar.remove(cookies.clear_cookie(&ss_cookie_name));

    let svc = state.social_service();

    let cb_state = match svc
        .validate_callback_state(&state_hash, &provider_code)
        .await
    {
        Ok(s) => s,
        Err(_) => {
            let registration = super::register::has_registration(&state, &jar)
                || super::register::request_context_client(&state, &jar).is_some();
            return social_error(jar, registration, "invalid_state");
        }
    };
    let (registration_redirect, existing_only) =
        registration_target(&cb_state.social_value.redirect);
    let return_to_registration = registration_redirect.split('?').next() == Some("/sso/register");
    if params.error.is_some() || params.code.is_none() {
        let error = if params.error.is_some() {
            "provider_error"
        } else {
            "missing_code"
        };
        return social_error(jar, return_to_registration, error);
    }
    let code = params.code.as_deref().unwrap_or_default();

    let token_result = match svc
        .exchange_code(
            &cb_state.provider,
            code,
            &cb_state.social_value.code_verifier,
        )
        .await
    {
        Ok(t) => t,
        Err(SocialLoginError::TokenExchangeFailed(e)) => {
            tracing::error!("Token exchange: {e}");
            return social_error(jar, return_to_registration, "token_exchange_failed");
        }
        Err(_) => return social_error(jar, return_to_registration, "token_exchange_failed"),
    };

    let user_info = match svc
        .fetch_userinfo(
            &cb_state.provider,
            &token_result,
            cb_state.social_value.nonce.as_deref(),
            cb_state.social_value.reauthenticate_after,
        )
        .await
    {
        Ok(u) => u,
        Err(SocialLoginError::Dependency(error)) => {
            tracing::error!(%error, "Upstream signing keys unavailable");
            if return_to_registration {
                return social_error(jar, true, "service_unavailable");
            }
            return axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
        Err(SocialLoginError::UserinfoFailed(e)) => {
            tracing::error!("Userinfo: {e}");
            return social_error(jar, return_to_registration, "userinfo_failed");
        }
        Err(_) => return social_error(jar, return_to_registration, "userinfo_failed"),
    };

    if let Some(session_id) = cb_state.social_value.reauth_session {
        let session = match crate::web::session::extract_browser_session(&state, &jar).await {
            Ok(Some(s)) if s.id == session_id => s,
            Ok(_) => return Redirect::to("/account/reauth").into_response(),
            Err(e) => return e.into_response(),
        };
        let result = crate::service::mfa::record_oidc_reauthentication(
            &state,
            &session,
            cb_state.provider.provider.id,
            &user_info.sub,
            user_info.authenticated_at,
        )
        .await;
        if let Err(e) = result {
            return match e {
                crate::service::ManagementError::Invalid(code) => {
                    let mut target = "/sso/error".to_string();
                    pero_utils::encode::append_query_param(&mut target, "code", code);
                    (jar, Redirect::to(&target)).into_response()
                }
                error => (jar, crate::web::util::dependency_error(error)).into_response(),
            };
        }
        let mut target = if session.mfa_required && session.mfa_verified_at.is_none() {
            "/sso/mfa"
        } else {
            "/account/reauth"
        }
        .to_string();
        pero_utils::encode::append_query_param(
            &mut target,
            "redirect",
            &cb_state.social_value.redirect,
        );
        return (jar, Redirect::to(&target)).into_response();
    }

    if let Some((user_id, session_id)) = cb_state.social_value.account_link {
        let session = match crate::web::session::extract_session(&state, &jar).await {
            Ok(Some(session)) if session.user_id == user_id && session.id == session_id => session,
            Ok(_) => {
                return Redirect::to("/account/login?redirect=%2Faccount%2Fidentities")
                    .into_response();
            }
            Err(status) => return status.into_response(),
        };
        let result = svc
            .bind_social_identity(&session, cb_state.provider.provider.id, &user_info)
            .await;
        let target = match result {
            Ok(_) => "/account/identities",
            Err(SocialLinkError::ReauthenticationRequired) => {
                return (
                    jar,
                    Redirect::to("/account/reauth?redirect=%2Faccount%2Fidentities"),
                )
                    .into_response();
            }
            Err(SocialLinkError::InvalidSession) => {
                "/account/login?redirect=%2Faccount%2Fidentities"
            }
            Err(SocialLinkError::ProviderAlreadyLinked) => {
                "/account/identities?error=provider_already_linked"
            }
            Err(SocialLinkError::IdentityTaken) => {
                "/account/identities?error=social_identity_taken"
            }
            Err(SocialLinkError::Internal(error)) => {
                return crate::web::util::dependency_error(error);
            }
        };
        return (jar, Redirect::to(target)).into_response();
    }

    let request = match validate_login_context(
        &state,
        &jar,
        &cb_state.social_value.redirect,
        cb_state.auth_request_id,
    )
    .await
    {
        Ok(request) => request,
        Err(response) => return *response,
    };
    let authenticated_at = user_info.authenticated_at;
    let resolution = match svc
        .resolve_identity(
            &cb_state.provider,
            &user_info,
            cb_state.auth_request_id,
            &cb_state.social_value.redirect,
            if existing_only {
                LoginPurpose::ExistingAccount
            } else if return_to_registration {
                LoginPurpose::Registration
            } else {
                LoginPurpose::Login
            },
        )
        .await
    {
        Ok(r) => r,
        Err(SocialLoginError::Internal(e)) => {
            tracing::error!("Identity: {e}");
            return social_error(jar, return_to_registration, "identity_error");
        }
        Err(_) => return social_error(jar, return_to_registration, "identity_error"),
    };

    match resolution {
        IdentityResolution::Resolved {
            user_id,
            identity_id,
        } => {
            finish_social_login(
                &state,
                jar,
                user_id,
                identity_id,
                cb_state.provider.provider.id,
                &SocialLoginContext {
                    redirect: cb_state.social_value.redirect,
                    request: request.as_ref(),
                    ip,
                    authenticated_at,
                    user_agent: crate::web::util::user_agent(&headers),
                },
            )
            .await
        }
        IdentityResolution::AlreadyBound => social_error(jar, true, "social_identity_taken"),
        IdentityResolution::NeedsAccountLink { nonce } => {
            // Continue the verified callback only in the initiating browser.
            let cookie = cookies.build_short_lived_cookie(
                SOCIAL_LINK_COOKIE,
                &nonce,
                state.config.oauth2.authorization_request_ttl_seconds,
            );
            (jar.add(cookie), Redirect::to("/sso/social/link")).into_response()
        }
        IdentityResolution::NeedsRegistration => {
            if existing_only {
                return social_error(jar, true, "existing_identity_required");
            }
            // Only callbacks started for a specific enrollment or invitation
            // may reuse its cookies. A normal login starts a new enrollment.
            let jar = if !return_to_registration {
                let jar = super::register::clear_flow(jar);
                if let Some(request) = &request {
                    match super::register::application_context_cookie(&state, request).await {
                        Ok(cookie) => jar.add(cookie),
                        Err(crate::service::ManagementError::Invalid(code)) => {
                            return social_error(jar, true, code);
                        }
                        Err(e) => return crate::web::util::management_response(Err(e)),
                    }
                } else {
                    jar
                }
            } else {
                jar
            };
            super::register::social(
                &state,
                jar,
                cb_state.provider.provider.id,
                user_info,
                request.as_ref(),
            )
            .await
        }
    }
}

pub async fn link_get(State(state): State<AppState>, jar: CookieJar) -> Response {
    let Some(nonce) = jar.get(SOCIAL_LINK_COOKIE).map(|c| c.value().to_owned()) else {
        return Redirect::to(&login_error_url("social_link_expired")).into_response();
    };
    render_social_link(&state, jar, &nonce, "").await
}

pub async fn link_post(
    State(state): State<AppState>,
    jar: CookieJar,
    ClientIp(ip): ClientIp,
    headers: axum::http::HeaderMap,
    Form(form): Form<SocialLinkForm>,
) -> Response {
    if !jar.get(SOCIAL_LINK_COOKIE).is_some_and(|cookie| {
        pero_utils::crypto::constant_time_eq(cookie.value().as_bytes(), form.nonce.as_bytes())
    }) {
        return Redirect::to(&login_error_url("social_link_expired")).into_response();
    }
    let svc = state.social_service();

    let link = match svc.load_social_link(&form.nonce).await {
        Ok(Some(v)) => v,
        Ok(None) => return Redirect::to(&login_error_url("social_link_expired")).into_response(),
        Err(SocialLoginError::Internal(e)) => {
            tracing::error!("Load social link: {e}");
            return Redirect::to("/sso/error?code=internal_error").into_response();
        }
        Err(_) => return Redirect::to("/sso/error?code=internal_error").into_response(),
    };

    if !state.web_security().verify_csrf(&jar, &form.csrf_token) {
        return render_social_link(&state, jar, &form.nonce, "invalid_csrf").await;
    }

    let user_id = match Uuid::parse_str(&link.user_id) {
        Ok(id) => id,
        Err(_) => return Redirect::to(&login_error_url("social_link_expired")).into_response(),
    };
    let provider_id = match Uuid::parse_str(&link.provider_id) {
        Ok(id) => id,
        Err(_) => return Redirect::to(&login_error_url("social_link_expired")).into_response(),
    };
    let auth_request_id = match link.auth_request_id.as_deref() {
        Some(raw) => match Uuid::parse_str(raw) {
            Ok(id) => Some(id),
            Err(_) => return Redirect::to(&login_error_url("social_link_expired")).into_response(),
        },
        None => None,
    };

    let request = match validate_login_context(&state, &jar, &link.redirect, auth_request_id).await
    {
        Ok(request) => request,
        Err(response) => return *response,
    };

    let user = match crate::db::entity::users::Entity::find_by_id(user_id)
        .one(&state.db)
        .await
    {
        Ok(Some(u)) if u.deleted_at.is_none() && u.status == UserStatus::Active => u,
        Ok(_) => return render_social_link(&state, jar, &form.nonce, "user_not_found").await,
        Err(e) => {
            tracing::error!("Find social link user: {e}");
            return render_social_link(&state, jar, &form.nonce, "internal_error").await;
        }
    };

    let password_identity = match verify_password_for_user(&state, ip, &user, &form.password).await
    {
        Ok(identity) => identity,
        Err(LoginFormError::ServiceUnavailable) => {
            return axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
        Err(LoginFormError::Internal) => {
            return axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
        Err(error) => {
            let key = error.message_key().unwrap_or("invalid_credentials");
            return render_social_link(&state, jar, &form.nonce, key).await;
        }
    };

    let identity_id = match svc
        .link_social_identity(&password_identity, provider_id, &link)
        .await
    {
        Ok(id) => id,
        Err(SocialLinkError::ReauthenticationRequired) => {
            return Redirect::to("/account/login?redirect=%2Faccount%2Fidentities").into_response();
        }
        Err(SocialLinkError::InvalidSession) => {
            return render_social_link(&state, jar, &form.nonce, "unauthorized").await;
        }
        Err(SocialLinkError::ProviderAlreadyLinked) => {
            return render_social_link(&state, jar, &form.nonce, "provider_already_linked").await;
        }
        Err(SocialLinkError::IdentityTaken) => {
            return render_social_link(&state, jar, &form.nonce, "social_identity_taken").await;
        }
        Err(SocialLinkError::Internal(e)) => {
            tracing::error!("Link social identity: {e}");
            return render_social_link(&state, jar, &form.nonce, "internal_error").await;
        }
    };

    svc.delete_social_link_cache(&form.nonce).await;
    let jar = jar.remove(state.cookie_factory().clear_cookie(SOCIAL_LINK_COOKIE));

    finish_social_login(
        &state,
        jar,
        user.id,
        identity_id,
        provider_id,
        &SocialLoginContext {
            redirect: link.redirect,
            request: request.as_ref(),
            ip,
            authenticated_at: None,
            user_agent: crate::web::util::user_agent(&headers),
        },
    )
    .await
}

#[derive(Debug, serde::Deserialize)]
pub struct CallbackParams {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
}

async fn validate_login_context(
    state: &AppState,
    jar: &CookieJar,
    redirect: &str,
    auth_request_id: Option<Uuid>,
) -> Result<Option<crate::db::entity::authorization_requests::Model>, Box<Response>> {
    let (redirect, _) = registration_target(redirect);
    let registration = redirect.split('?').next() == Some("/sso/register");
    let flow_matches = !registration
        || super::register::flow_matches(state, jar, redirect.strip_prefix("/sso/register?flow="));
    if flow_matches {
        if let Some(id) = auth_request_id {
            let request = super::register::active_request(state, jar)
                .await
                .map_err(|e| Box::new(crate::web::util::management_response(Err(e))))?;
            if let Some(request) = request.filter(|request| request.id == id) {
                return Ok(Some(request));
            }
        } else {
            return Ok(None);
        }
    }
    Err(Box::new(social_error(
        jar.clone(),
        registration,
        "enrollment_unavailable",
    )))
}

pub(super) fn social_error(jar: CookieJar, registration: bool, code: &str) -> Response {
    let mut target = if registration {
        "/sso/register"
    } else {
        "/sso/error"
    }
    .to_owned();
    let key = if registration { "error" } else { "code" };
    pero_utils::encode::append_query_param(&mut target, key, code);
    (jar, Redirect::to(&target)).into_response()
}

struct SocialLoginContext<'a> {
    redirect: String,
    request: Option<&'a crate::db::entity::authorization_requests::Model>,
    ip: Option<ipnetwork::IpNetwork>,
    authenticated_at: Option<time::OffsetDateTime>,
    user_agent: Option<String>,
}

async fn finish_social_login(
    state: &AppState,
    jar: CookieJar,
    user_id: Uuid,
    identity_id: Uuid,
    provider_id: Uuid,
    ctx: &SocialLoginContext<'_>,
) -> Response {
    let session_svc = state.session_service();
    let registration = ctx.redirect.split('?').next() == Some("/sso/register");
    let (token, _) = match session_svc
        .create_social(
            user_id,
            identity_id,
            provider_id,
            ctx.ip,
            ctx.authenticated_at,
            ctx.user_agent.clone(),
        )
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("Session: {e}");
            return social_error(jar, registration, "internal_error");
        }
    };

    let redirect_target = if registration {
        "/sso/register".to_owned()
    } else if let Some(request) = ctx.request {
        match crate::web::login_flow::enrollment_resume_target(state, request, None, Some(&token)) {
            Ok(target) => target,
            Err(error) => return crate::web::util::dependency_error(error),
        }
    } else {
        crate::web::util::safe_redirect(&ctx.redirect)
    };
    crate::web::login_flow::finish_login(state, jar, &token, &redirect_target).await
}

async fn render_social_link(
    state: &AppState,
    jar: CookieJar,
    nonce: &str,
    error: &str,
) -> Response {
    let svc = state.social_service();

    let link = match svc.load_social_link(nonce).await {
        Ok(Some(v)) => v,
        Ok(None) => return Redirect::to(&login_error_url("social_link_expired")).into_response(),
        Err(SocialLoginError::Internal(e)) => {
            tracing::error!("Load social link: {e}");
            return Redirect::to("/sso/error?code=internal_error").into_response();
        }
        Err(_) => return Redirect::to("/sso/error?code=internal_error").into_response(),
    };

    let user_id = match Uuid::parse_str(&link.user_id) {
        Ok(id) => id,
        Err(_) => return Redirect::to(&login_error_url("social_link_expired")).into_response(),
    };
    let has_password = match LoginService::new(&state.db, &state.cache)
        .find_password_identity(user_id)
        .await
    {
        Ok(identity) => identity
            .is_some_and(|identity| identity.password_hash.is_some_and(|hash| !hash.is_empty())),
        Err(_) => return axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    let (jar, csrf_token) = state.web_security().ensure_csrf(jar);
    let tpl = SocialLinkView {
        has_password,
        csrf_token,
        nonce: nonce.to_owned(),
        provider_name: link.provider_name,
        account_email: link.email.unwrap_or_default(),
        display_name: link.name.unwrap_or_else(|| "Pero".to_owned()),
        error: error.to_owned(),
    };
    (jar, pero_api_axum::form::view("SocialLinkView", tpl)).into_response()
}

fn login_error_url(error: &str) -> String {
    let mut url = "/sso/login".to_owned();
    pero_utils::encode::append_query_param(&mut url, "error", error);
    url
}
