use askama::Template;
use axum::extract::{Query, State};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

use crate::domain::identity::store::{UserRepo, VerifyPayload};
use crate::handler::sso::common::render_tpl;
use crate::shared::constants::cache_keys::{EMAIL_VERIFY_PREFIX, PHONE_VERIFY_PREFIX};
use crate::shared::error::AppError;
use crate::shared::state::AppState;

#[derive(Debug, Deserialize)]
pub struct VerifyQuery {
    pub token: Option<String>,
}

#[derive(Template, Debug)]
#[template(path = "sso/verification.html")]
pub struct VerificationTemplate {
    pub channel: String,
    pub status: String,
    pub account: String,
}

pub async fn verify_email_get(
    State(state): State<AppState>,
    Query(query): Query<VerifyQuery>,
) -> Result<Response, AppError> {
    verify_get_inner(&state, query, "email").await
}

pub async fn verify_phone_get(
    State(state): State<AppState>,
    Query(query): Query<VerifyQuery>,
) -> Result<Response, AppError> {
    verify_get_inner(&state, query, "phone").await
}

async fn verify_get_inner(
    state: &AppState,
    query: VerifyQuery,
    channel: &str,
) -> Result<Response, AppError> {
    let token = match query.token {
        Some(t) if !t.is_empty() => t,
        _ => {
            let tpl = VerificationTemplate {
                channel: channel.to_string(),
                status: "invalid".to_string(),
                account: String::new(),
            };
            return Ok(render_tpl(&tpl)?.into_response());
        }
    };

    let (status, account) = if channel == "email" {
        validate_email_token(state, &token).await
    } else {
        validate_phone_token(state, &token).await
    };

    let tpl = VerificationTemplate {
        channel: channel.to_string(),
        status,
        account,
    };
    Ok(render_tpl(&tpl)?.into_response())
}

async fn validate_email_token(state: &AppState, token: &str) -> (String, String) {
    let payload: Option<VerifyPayload> =
        crate::shared::utils::validate_cached_token(&state.cache, EMAIL_VERIFY_PREFIX, token).await;
    match payload {
        Some(payload) => {
            let user = match UserRepo::find_by_id(&state.db, payload.user_id).await {
                Ok(Some(u)) => u,
                _ => return ("invalid".to_string(), String::new()),
            };

            if user.email_verified {
                let key = format!("{EMAIL_VERIFY_PREFIX}{token}");
                let _ = crate::infra::cache::del(&state.cache, &key).await;
                return ("success".to_string(), user.email.unwrap_or_default());
            };

            if let Some(email) = user.email {
                match UserRepo::set_email_verified(&state.db, payload).await {
                    Ok(_) => {
                        let key = format!("{EMAIL_VERIFY_PREFIX}{token}");
                        let _ = crate::infra::cache::del(&state.cache, &key).await;
                        ("success".to_string(), email)
                    }
                    Err(_) => ("invalid".to_string(), String::new()),
                }
            } else {
                ("invalid".to_string(), String::new())
            }
        }
        None => ("expired".to_string(), String::new()),
    }
}

async fn validate_phone_token(state: &AppState, token: &str) -> (String, String) {
    let payload: Option<VerifyPayload> =
        crate::shared::utils::validate_cached_token(&state.cache, PHONE_VERIFY_PREFIX, token).await;
    match payload {
        Some(payload) => {
            let user = match UserRepo::find_by_id(&state.db, payload.user_id).await {
                Ok(Some(u)) => u,
                _ => return ("invalid".to_string(), String::new()),
            };

            if user.phone_verified {
                let key = format!("{PHONE_VERIFY_PREFIX}{token}");
                let _ = crate::infra::cache::del(&state.cache, &key).await;
                return ("success".to_string(), String::new());
            }

            if let Some(phone) = user.phone {
                match UserRepo::set_phone_verified(&state.db, payload).await {
                    Ok(_) => {
                        let key = format!("{PHONE_VERIFY_PREFIX}{token}");
                        let _ = crate::infra::cache::del(&state.cache, &key).await;
                        ("success".to_string(), phone)
                    }
                    Err(_) => ("invalid".to_string(), String::new()),
                }
            } else {
                ("invalid".to_string(), String::new())
            }
        }
        None => ("expired".to_string(), String::new()),
    }
}

pub async fn verify_phone_post(
    State(state): State<AppState>,
    Query(query): Query<VerifyQuery>,
) -> Result<Response, AppError> {
    let token = query.token.unwrap_or_default();
    let payload: Option<VerifyPayload> = crate::shared::utils::consume_cached_token(&state.cache, PHONE_VERIFY_PREFIX, &token).await;

    let payload = match payload {
        Some(p) => p,
        None => {
            let tpl = VerificationTemplate {
                channel: "phone".to_string(),
                status: "invalid".to_string(),
                account: String::new(),
            };
            return Ok(render_tpl(&tpl)?.into_response());
        }
    };

    let user = UserRepo::find_by_id(&state.db, payload.user_id)
        .await?
        .ok_or(AppError::Unauthorized)?;

    UserRepo::set_phone_verified(&state.db, payload).await?;

    let tpl = VerificationTemplate {
        channel: "phone".to_string(),
        status: "success".to_string(),
        account: user.phone.clone().unwrap_or_default(),
    };
    Ok(render_tpl(&tpl)?.into_response())
}

#[utoipa::path(
    post,
    path = "/api/identity/send-verify-email",
    tag = "Identity",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Verification email sent", body = crate::api::response::MessageResponse),
        (status = 401, description = "Unauthorized"),
        (status = 409, description = "Email already verified"),
    )
)]
pub async fn send_verify_email_post(
    State(state): State<AppState>,
    auth_user: crate::api::extractors::AuthUser,
) -> Result<axum::Json<crate::api::response::MessageResponse>, AppError> {
    let user = UserRepo::find_by_id(&state.db, auth_user.user_id)
        .await?
        .ok_or(AppError::Unauthorized)?;

    if user.email_verified {
        return Err(crate::domain::identity::error::email_already_verified());
    }

    let email = match user.email.clone() {
        Some(email) => email,
        None => return Err(crate::domain::identity::error::email_not_set()),
    };

    let payload = VerifyPayload {
        user_id: user.id,
        value: email.to_string(),
    };
    let _token = crate::shared::utils::generate_token_and_cache(
        &state.cache,
        EMAIL_VERIFY_PREFIX,
        &payload,
        state.config.sso.email_verify_ttl_seconds,
    )
    .await?;

    tracing::info!(
        user_id = %user.id,
        "email verification token generated (email delivery stub)"
    );

    Ok(axum::Json(crate::api::response::MessageResponse::success(
        "Verification email sent.",
    )))
}

#[utoipa::path(
    post,
    path = "/api/identity/send-verify-phone",
    tag = "Identity",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Verification SMS sent", body = crate::api::response::MessageResponse),
        (status = 401, description = "Unauthorized"),
        (status = 409, description = "Phone already verified"),
    )
)]
pub async fn send_verify_phone_post(
    State(state): State<AppState>,
    auth_user: crate::api::extractors::AuthUser,
) -> Result<axum::Json<crate::api::response::MessageResponse>, AppError> {
    let user = UserRepo::find_by_id(&state.db, auth_user.user_id)
        .await?
        .ok_or(AppError::Unauthorized)?;

    let phone = user
        .phone
        .as_deref()
        .ok_or_else(crate::domain::identity::error::phone_not_set)?;

    if user.phone_verified {
        return Err(crate::domain::identity::error::phone_already_verified());
    }

    let payload = VerifyPayload {
        user_id: user.id,
        value: phone.to_string(),
    };
    let _token = crate::shared::utils::generate_token_and_cache(
        &state.cache,
        PHONE_VERIFY_PREFIX,
        &payload,
        state.config.sso.phone_verify_ttl_seconds,
    )
    .await?;

    tracing::info!(
        user_id = %user.id,
        "phone verification token generated (SMS delivery stub)"
    );

    Ok(axum::Json(crate::api::response::MessageResponse::success(
        "Verification SMS sent.",
    )))
}
