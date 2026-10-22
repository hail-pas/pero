use axum_extra::extract::cookie::CookieJar;
use ipnetwork::IpNetwork;

use crate::db::entity::{identities, users};
use crate::service::login::{LoginService, PasswordLoginError};
use crate::state::app::AppState;
use crate::web::sso::template::LoginForm;

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

    let login_svc = LoginService::new(&state.db, &state.cache);
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
        .map(|result| result.token)
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
