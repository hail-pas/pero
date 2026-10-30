use axum_extra::extract::cookie::CookieJar;
use ipnetwork::IpNetwork;

use crate::db::entity::{identities, users};
use crate::service::login::{LoginService, PasswordLoginError};
use crate::state::app::AppState;
use crate::web::sso::dto::LoginForm;

/// Bound anonymous state creation across OAuth authorization and upstream login starts.
pub async fn check_login_start_rate_limit(
    state: &AppState,
    source: pero_api_axum::extractor::ClientIp,
) -> Result<(), axum::http::StatusCode> {
    use axum::http::StatusCode;
    use pero_cache_redis::{RateLimitError, enforce_rate_limit, rate_limit_key::rl_login_start_ip};

    let key = rl_login_start_ip
        .key(&source.to_string())
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    match enforce_rate_limit(&state.cache, &key, 60).await {
        Ok(()) => Ok(()),
        Err(RateLimitError::Denied { .. }) => Err(StatusCode::TOO_MANY_REQUESTS),
        Err(RateLimitError::Redis(error)) => {
            tracing::error!(%error, "Login-start rate limit unavailable");
            Err(StatusCode::SERVICE_UNAVAILABLE)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginFormError {
    InvalidCsrf,
    InvalidCredentials,
    RateLimited,
    AccountLocked,
    NoPasswordIdentity,
    ServiceUnavailable,
    Internal,
}

impl LoginFormError {
    pub fn message_key(self) -> Option<&'static str> {
        match self {
            Self::InvalidCsrf => Some("invalid_csrf"),
            Self::InvalidCredentials => Some("invalid_credentials"),
            Self::RateLimited => Some("rate_limited"),
            Self::AccountLocked => Some("account_locked"),
            Self::NoPasswordIdentity => Some("no_password_identity"),
            Self::ServiceUnavailable | Self::Internal => None,
        }
    }
}

pub async fn authenticate_password_form(
    state: &AppState,
    jar: &CookieJar,
    ip: Option<IpNetwork>,
    form: &LoginForm,
    user_agent: Option<String>,
) -> Result<String, LoginFormError> {
    if !state.web_security().verify_csrf(jar, &form.csrf_token) {
        return Err(LoginFormError::InvalidCsrf);
    }

    if !matches!(
        form.identifier_type.as_str(),
        "email" | "phone" | "username"
    ) {
        return Err(LoginFormError::InvalidCredentials);
    }

    let login_svc = LoginService::new(&state.db, &state.cache).with_user_agent(user_agent);
    let session_svc = state.session_service();

    login_svc
        .password_login(
            &session_svc,
            ip,
            &form.identifier_type,
            &form.identifier,
            &form.password,
        )
        .await
        .map_err(LoginFormError::from)
}

pub async fn verify_password_for_user(
    state: &AppState,
    ip: Option<IpNetwork>,
    user: &users::Model,
    password: &str,
) -> Result<identities::Model, LoginFormError> {
    let login_svc = LoginService::new(&state.db, &state.cache);
    login_svc
        .check_rate_limit(ip, "")
        .await
        .map_err(LoginFormError::from)?;

    if login_svc
        .is_account_locked(user.id)
        .await
        .map_err(LoginFormError::from)?
    {
        login_svc.record_failure(user.id, None, None, ip).await;
        return Err(LoginFormError::AccountLocked);
    }

    let identity = match login_svc
        .find_password_identity(user.id)
        .await
        .map_err(LoginFormError::from)?
    {
        Some(id) => id,
        None => {
            login_svc.record_failure(user.id, None, None, ip).await;
            return Err(LoginFormError::NoPasswordIdentity);
        }
    };

    if !crate::service::password::PasswordIdentityService::verify_password_hash(
        password,
        identity.password_hash.as_deref(),
    )
    .await
    .map_err(|_| LoginFormError::ServiceUnavailable)?
    {
        login_svc.incr_failure(user.id).await;
        login_svc
            .record_failure(user.id, Some(identity.id), None, ip)
            .await;
        return Err(LoginFormError::InvalidCredentials);
    }

    login_svc.clear_failures(user.id).await;
    Ok(identity)
}

impl From<PasswordLoginError> for LoginFormError {
    fn from(value: PasswordLoginError) -> Self {
        match value {
            PasswordLoginError::RateLimited => Self::RateLimited,
            PasswordLoginError::ServiceUnavailable => Self::ServiceUnavailable,
            PasswordLoginError::InvalidCredentials => Self::InvalidCredentials,
            PasswordLoginError::AccountLocked => Self::AccountLocked,
            PasswordLoginError::InternalError(_) => Self::Internal,
        }
    }
}

/// Complete primary login; the target application enforces its MFA policy.
pub async fn finish_login(
    state: &AppState,
    jar: CookieJar,
    token: &str,
    redirect: &str,
) -> axum::response::Response {
    use axum::response::{IntoResponse, Redirect};
    let jar = jar.add(state.cookie_factory().build_session_cookie(token));
    let session = match crate::web::session::extract_browser_session(state, &jar).await {
        Ok(Some(session)) => session,
        Ok(None) => return axum::http::StatusCode::UNAUTHORIZED.into_response(),
        Err(status) => return status.into_response(),
    };
    let mut target = crate::web::util::safe_redirect(redirect);
    // Challenge direct dashboard navigation here. OAuth destinations enforce the
    // target application's policy after resume, independently of the user's role.
    let target_path = target.split('?').next().unwrap_or("");
    let management_pending = session.mfa_required
        && session.mfa_verified_at.is_none()
        && (target_path == "/dashboard" || target_path.starts_with("/dashboard/"));
    if (session.recovery_pending || management_pending)
        && !matches!(
            target.split('?').next(),
            Some("/sso/mfa" | "/account/security" | "/account/reauth")
        )
    {
        let mut challenge = "/sso/mfa".to_owned();
        pero_utils::encode::append_query_param(&mut challenge, "redirect", &target);
        target = challenge;
    }
    (jar, Redirect::to(&target)).into_response()
}
