use axum::extract::State;
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::cookie::CookieJar;

use crate::db::enums::ContactChangeType;
use crate::service::contact::{ContactChannel, ContactError, ContactVerificationService};
use crate::state::app::AppState;
use crate::web::session::extract_session;
use pero_api_axum::{json_ok, json_ok_with_data, json_ok_with_error};

#[derive(Debug, serde::Deserialize)]
pub struct SendVerifyForm {
    pub csrf_token: String,
}

#[derive(Debug, serde::Deserialize)]
pub struct CancelContactForm {
    pub csrf_token: String,
    pub nonce: String,
}

#[derive(Debug, serde::Deserialize)]
pub struct VerifyContactNonceForm {
    pub csrf_token: String,
    pub nonce: String,
    pub code: String,
}

#[derive(Debug, serde::Deserialize)]
pub struct VerifyContactQuery {
    pub nonce: String,
}

#[derive(Debug, serde::Deserialize)]
pub struct ChangeContactForm {
    pub csrf_token: String,
    pub value: String,
}

pub async fn send_verify_email(
    State(state): State<AppState>,
    jar: CookieJar,
    axum::Form(form): axum::Form<SendVerifyForm>,
) -> Response {
    send_current_contact_verification(&state, jar, form, ContactChannel::Email).await
}

pub async fn send_verify_phone(
    State(state): State<AppState>,
    jar: CookieJar,
    axum::Form(form): axum::Form<SendVerifyForm>,
) -> Response {
    send_current_contact_verification(&state, jar, form, ContactChannel::Phone).await
}

pub async fn change_email(
    State(state): State<AppState>,
    jar: CookieJar,
    axum::Form(form): axum::Form<ChangeContactForm>,
) -> Response {
    change_contact(&state, jar, form, ContactChannel::Email).await
}

pub async fn change_phone(
    State(state): State<AppState>,
    jar: CookieJar,
    axum::Form(form): axum::Form<ChangeContactForm>,
) -> Response {
    change_contact(&state, jar, form, ContactChannel::Phone).await
}

pub async fn verify_contact(
    State(state): State<AppState>,
    jar: CookieJar,
    axum::Form(form): axum::Form<VerifyContactNonceForm>,
) -> Response {
    if !state.web_security().verify_csrf(&jar, &form.csrf_token) {
        return json_ok_with_error("invalid_csrf");
    }

    let session = match extract_session(&state, &jar).await {
        Ok(Some(s)) => s,
        Ok(None) => return json_ok_with_error("unauthorized"),
        Err(status) => return status.into_response(),
    };

    let svc = ContactVerificationService::new(&state.db, &state.cache);
    match svc
        .verify_contact(session.user_id, &form.nonce, &form.code)
        .await
    {
        Ok(_) => json_ok(),
        Err(e) => contact_error_response(&e),
    }
}

pub async fn verify_contact_get(
    State(state): State<AppState>,
    jar: CookieJar,
    axum::extract::Query(query): axum::extract::Query<VerifyContactQuery>,
) -> Response {
    let session = match extract_session(&state, &jar).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            let mut target = "/account/profile/verify-contact".to_owned();
            pero_utils::encode::append_query_param(&mut target, "nonce", &query.nonce);
            let mut login = "/account/login".to_owned();
            pero_utils::encode::append_query_param(&mut login, "redirect", &target);
            return Redirect::to(&login).into_response();
        }
        Err(status) => return status.into_response(),
    };

    let svc = ContactVerificationService::new(&state.db, &state.cache);

    let req = match svc.load_pending_request(&query.nonce).await {
        Ok(Some(r)) => r,
        Ok(None) => return Redirect::to("/account/profile").into_response(),
        Err(_) => return axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };

    if req.user_id != session.user_id {
        return Redirect::to("/account/profile").into_response();
    }

    if req.expires_at < time::OffsetDateTime::now_utc() {
        return Redirect::to("/account/profile").into_response();
    }

    let user = match svc.load_active_user(session.user_id).await {
        Ok(u) => u,
        Err(ContactError::UserNotFound) => return Redirect::to("/account/login").into_response(),
        Err(_) => return axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };

    let masked_value = match req.change_type {
        ContactChangeType::Email => mask_email(&req.new_value),
        ContactChangeType::Phone => mask_phone(&req.new_value),
    };

    let change_type_label = match req.change_type {
        ContactChangeType::Email => "email",
        ContactChangeType::Phone => "phone",
    };

    let layout = super::dto::AccountLayout::from_user(&state.db, &user).await;

    let (jar, csrf_token) = state.web_security().ensure_csrf(jar);

    let tpl = crate::web::account::dto::VerifyContactView {
        layout,
        csrf_token,
        change_type: change_type_label.to_owned(),
        masked_value,
        nonce: req.nonce,
    };
    (jar, pero_api_axum::form::view("VerifyContactView", tpl)).into_response()
}

pub async fn cancel_contact(
    State(state): State<AppState>,
    jar: CookieJar,
    axum::Form(form): axum::Form<CancelContactForm>,
) -> Response {
    if !state.web_security().verify_csrf(&jar, &form.csrf_token) {
        return json_ok_with_error("invalid_csrf");
    }

    let session = match extract_session(&state, &jar).await {
        Ok(Some(s)) => s,
        Ok(None) => return json_ok_with_error("unauthorized"),
        Err(status) => return status.into_response(),
    };

    let svc = ContactVerificationService::new(&state.db, &state.cache);
    match svc.cancel_contact(session.user_id, &form.nonce).await {
        Ok(()) => json_ok(),
        Err(e) => contact_error_response(&e),
    }
}

async fn send_current_contact_verification(
    state: &AppState,
    jar: CookieJar,
    form: SendVerifyForm,
    channel: ContactChannel,
) -> Response {
    if !state.web_security().verify_csrf(&jar, &form.csrf_token) {
        return json_ok_with_error("invalid_csrf");
    }

    let session = match extract_session(state, &jar).await {
        Ok(Some(s)) => s,
        Ok(None) => return json_ok_with_error("unauthorized"),
        Err(status) => return status.into_response(),
    };

    let mut svc = ContactVerificationService::new(&state.db, &state.cache);
    let user = match svc.load_active_user(session.user_id).await {
        Ok(u) => u,
        Err(e) => return contact_error_response(&e),
    };

    let value = match channel.current_value(&user) {
        Some(v) => v.to_owned(),
        None => return json_ok_with_error(no_value_error(channel)),
    };

    if channel.is_verified(&user) {
        return json_ok_with_error("already_verified");
    }

    create_and_send_contact_request(state, &mut svc, user.id, channel, value).await
}

async fn change_contact(
    state: &AppState,
    jar: CookieJar,
    form: ChangeContactForm,
    channel: ContactChannel,
) -> Response {
    if !state.web_security().verify_csrf(&jar, &form.csrf_token) {
        return json_ok_with_error("invalid_csrf");
    }

    let new_value = form.value.trim().to_owned();
    if new_value.is_empty() {
        return json_ok_with_error(required_error(channel));
    }

    if !channel.is_valid_format(&new_value) {
        return json_ok_with_error(format_error(channel));
    }

    let session = match extract_session(state, &jar).await {
        Ok(Some(s)) => s,
        Ok(None) => return json_ok_with_error("unauthorized"),
        Err(status) => return status.into_response(),
    };

    let mut svc = ContactVerificationService::new(&state.db, &state.cache);
    let user = match svc.load_active_user(session.user_id).await {
        Ok(u) => u,
        Err(e) => return contact_error_response(&e),
    };

    if channel.current_value(&user) == Some(new_value.as_str()) {
        return json_ok_with_error(same_value_error(channel));
    }

    create_and_send_contact_request(state, &mut svc, user.id, channel, new_value).await
}

async fn create_and_send_contact_request(
    state: &AppState,
    svc: &mut ContactVerificationService<'_>,
    user_id: uuid::Uuid,
    channel: ContactChannel,
    value: String,
) -> Response {
    if state.config.notification.endpoint.is_empty() {
        return crate::web::util::dependency_error("Notifications are not configured");
    }
    if let Err(e) = svc.check_rate_limit(user_id, channel.key()).await {
        return contact_error_response(&e);
    }

    let (_, nonce) = match svc
        .create_contact_request(user_id, channel, value, Some(&state.config.sso.base_url))
        .await
    {
        Ok(r) => r,
        Err(e) => return contact_error_response(&e),
    };

    json_ok_with_data(serde_json::json!({"nonce": nonce}))
}

fn no_value_error(channel: ContactChannel) -> &'static str {
    match channel {
        ContactChannel::Email => "no_email",
        ContactChannel::Phone => "no_phone",
    }
}

fn required_error(channel: ContactChannel) -> &'static str {
    match channel {
        ContactChannel::Email => "email_required",
        ContactChannel::Phone => "phone_required",
    }
}

fn same_value_error(channel: ContactChannel) -> &'static str {
    match channel {
        ContactChannel::Email => "same_email",
        ContactChannel::Phone => "same_phone",
    }
}

fn format_error(channel: ContactChannel) -> &'static str {
    match channel {
        ContactChannel::Email => "email_invalid",
        ContactChannel::Phone => "phone_invalid",
    }
}

fn contact_error_to_json(e: &ContactError) -> &'static str {
    match e {
        ContactError::UserNotFound => "user_not_found",
        ContactError::SamePendingValue => "same_pending_value",
        ContactError::ContactTaken => "contact_taken",
        ContactError::RateLimited => "rate_limited",
        ContactError::ServiceUnavailable => "service_unavailable",
        ContactError::InvalidNonce => "invalid_nonce",
        ContactError::InvalidCode => "invalid_code",
        ContactError::CodeExpired => "code_expired",
        ContactError::SendFailed => "send_failed",
        ContactError::Internal(_) => "internal_error",
    }
}

fn contact_error_response(e: &ContactError) -> Response {
    match e {
        ContactError::ServiceUnavailable | ContactError::SendFailed => {
            crate::web::util::dependency_error("Contact verification unavailable")
        }
        ContactError::Internal(error) => crate::web::util::dependency_error(error),
        _ => json_ok_with_error(contact_error_to_json(e)),
    }
}

fn mask_email(email: &str) -> String {
    let Some(at_pos) = email.find('@') else {
        return "***".to_owned();
    };
    let local = &email[..at_pos];
    let domain = &email[at_pos..];
    let first = local.chars().next().unwrap_or('*');
    format!("{first}******{domain}")
}

fn mask_phone(phone: &str) -> String {
    let chars: Vec<char> = phone.chars().collect();
    if chars.len() >= 7 {
        let n = chars.len();
        format!(
            "{}{}{}****{}{}{}{}",
            chars[0],
            chars[1],
            chars[2],
            chars[n - 4],
            chars[n - 3],
            chars[n - 2],
            chars[n - 1]
        )
    } else {
        "***".to_owned()
    }
}
