use askama::Template;
use axum::extract::{Query, State};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

use crate::handler::sso::common::render_tpl;
use crate::shared::error::AppError;
use crate::shared::kv::KvStoreExt;
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
    let key = format!(
        "{}{token}",
        crate::shared::constants::cache_keys::EMAIL_VERIFY_PREFIX
    );
    let payload: Option<crate::domain::user::dto::VerifyPayload> =
        crate::shared::kv::KvStoreExt::get_json(&*state.repos.kv, &key)
            .await
            .ok()
            .flatten();
    match payload {
        Some(payload) => {
            let user = match state.repos.users.find_by_id(payload.user_id).await {
                Ok(Some(u)) => u,
                _ => return ("invalid".to_string(), String::new()),
            };

            if user.email_verified {
                let _ = state.repos.kv.del(&key).await;
                return ("success".to_string(), user.email.unwrap_or_default());
            };

            if let Some(email) = user.email {
                match state
                    .repos
                    .users
                    .set_email_verified(payload.user_id, &payload.value)
                    .await
                {
                    Ok(_) => {
                        let _ = state.repos.kv.del(&key).await;
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
    let key = format!(
        "{}{token}",
        crate::shared::constants::cache_keys::PHONE_VERIFY_PREFIX
    );
    let payload: Option<crate::domain::user::dto::VerifyPayload> =
        crate::shared::kv::KvStoreExt::get_json(&*state.repos.kv, &key)
            .await
            .ok()
            .flatten();
    match payload {
        Some(payload) => {
            let user = match state.repos.users.find_by_id(payload.user_id).await {
                Ok(Some(u)) => u,
                _ => return ("invalid".to_string(), String::new()),
            };

            if user.phone_verified {
                let _ = state.repos.kv.del(&key).await;
                return ("success".to_string(), String::new());
            }

            if let Some(phone) = user.phone {
                match state
                    .repos
                    .users
                    .set_phone_verified(payload.user_id, &payload.value)
                    .await
                {
                    Ok(_) => {
                        let _ = state.repos.kv.del(&key).await;
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
    let key = format!(
        "{}{token}",
        crate::shared::constants::cache_keys::PHONE_VERIFY_PREFIX
    );
    let payload: Option<crate::domain::user::dto::VerifyPayload> =
        state.repos.kv.get_json(&key).await.ok().flatten();

    let payload = match payload {
        Some(p) => {
            let _ = state.repos.kv.del(&key).await;
            p
        }
        None => {
            let tpl = VerificationTemplate {
                channel: "phone".to_string(),
                status: "invalid".to_string(),
                account: String::new(),
            };
            return Ok(render_tpl(&tpl)?.into_response());
        }
    };

    let user = state
        .repos
        .users
        .find_by_id(payload.user_id)
        .await?
        .ok_or(AppError::Unauthorized)?;

    state
        .repos
        .users
        .set_phone_verified(payload.user_id, &payload.value)
        .await?;

    let tpl = VerificationTemplate {
        channel: "phone".to_string(),
        status: "success".to_string(),
        account: user.phone.clone().unwrap_or_default(),
    };
    Ok(render_tpl(&tpl)?.into_response())
}

pub async fn send_verify_email_post(
    State(state): State<AppState>,
    auth_user: crate::api::extractors::AuthUser,
) -> Result<axum::Json<crate::api::response::MessageResponse>, AppError> {
    let user = state
        .repos
        .users
        .find_by_id(auth_user.user_id)
        .await?
        .ok_or(AppError::Unauthorized)?;

    if user.email_verified {
        return Err(crate::domain::user::error::email_already_verified());
    }

    let email = match user.email.clone() {
        Some(email) => email,
        None => return Err(crate::domain::user::error::email_not_set()),
    };

    let payload = crate::domain::user::dto::VerifyPayload {
        user_id: user.id,
        value: email.to_string(),
    };
    let _token = crate::shared::utils::generate_token_and_cache(
        &*state.repos.kv,
        crate::shared::constants::cache_keys::EMAIL_VERIFY_PREFIX,
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

pub async fn send_verify_phone_post(
    State(state): State<AppState>,
    auth_user: crate::api::extractors::AuthUser,
) -> Result<axum::Json<crate::api::response::MessageResponse>, AppError> {
    let user = state
        .repos
        .users
        .find_by_id(auth_user.user_id)
        .await?
        .ok_or(AppError::Unauthorized)?;

    let phone = user
        .phone
        .as_deref()
        .ok_or_else(crate::domain::user::error::phone_not_set)?;

    if user.phone_verified {
        return Err(crate::domain::user::error::phone_already_verified());
    }

    let payload = crate::domain::user::dto::VerifyPayload {
        user_id: user.id,
        value: phone.to_string(),
    };
    let _token = crate::shared::utils::generate_token_and_cache(
        &*state.repos.kv,
        crate::shared::constants::cache_keys::PHONE_VERIFY_PREFIX,
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
