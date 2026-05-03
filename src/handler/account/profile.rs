use askama::Template;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use validator::Validate;

use crate::api::extractors::ValidatedForm;
use crate::domain::identity::models::UpdateMeRequest;
use crate::domain::identity::dto::VerifyPayload;
use crate::handler::account::common;
use crate::handler::account::common::{AccountLayout, UserView};
use crate::shared::constants::cache_keys::{EMAIL_VERIFY_PREFIX, PHONE_VERIFY_PREFIX};
use crate::shared::error::AppError;
use crate::shared::patch::FieldUpdate;
use crate::shared::state::AppState;

#[derive(Template, Debug)]
#[template(path = "account/profile.html")]
pub struct ProfileTemplate {
    pub layout: AccountLayout,
    pub user: UserView,
}

#[derive(Debug, Deserialize, Validate)]
pub struct ProfileForm {
    #[serde(
        default,
        deserialize_with = "crate::shared::utils::empty_string_as_none"
    )]
    #[validate(email)]
    pub email: Option<String>,
    #[serde(
        default,
        deserialize_with = "crate::shared::utils::empty_string_as_none"
    )]
    #[validate(length(min = 1, max = 64))]
    pub nickname: Option<String>,
    #[serde(
        default,
        deserialize_with = "crate::shared::utils::empty_string_as_none"
    )]
    #[validate(
        length(max = 20),
        custom(function = "crate::shared::validation::validate_phone")
    )]
    pub phone: Option<String>,
    #[serde(
        default,
        deserialize_with = "crate::shared::utils::empty_string_as_none"
    )]
    #[validate(url)]
    pub avatar_url: Option<String>,
}

pub async fn profile_get(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let user = common::get_account_user(&state, &headers).await?;
    let tpl = ProfileTemplate {
        layout: AccountLayout::new("profile", &user),
        user: UserView::from_user(&user),
    };
    Ok(common::render_tpl(&tpl)?.into_response())
}

pub async fn profile_post(
    State(state): State<AppState>,
    headers: HeaderMap,
    ValidatedForm(form): ValidatedForm<ProfileForm>,
) -> Result<Response, AppError> {
    let user_id = common::get_account_user_id(&state, &headers).await?;
    let current = state.repos.users.find_by_id(user_id)
        .await?
        .ok_or(AppError::Unauthorized)?;

    let req = UpdateMeRequest {
        email: match form.email {
            Some(v) if v != current.email.clone().unwrap_or_default() => FieldUpdate::Set(v),
            Some(_) => FieldUpdate::Unchanged,
            None => {
                if current.email.is_some() {
                    FieldUpdate::Clear
                } else {
                    FieldUpdate::Unchanged
                }
            }
        },
        nickname: match form.nickname {
            Some(v) => FieldUpdate::Set(v),
            None => FieldUpdate::Clear,
        },
        avatar_url: match form.avatar_url {
            Some(v) => FieldUpdate::Set(v),
            None => FieldUpdate::Clear,
        },
        phone: match form.phone {
            Some(v) if v != current.phone.clone().unwrap_or_default() => FieldUpdate::Set(v),
            Some(_) => FieldUpdate::Unchanged,
            None => {
                if current.phone.is_some() {
                    FieldUpdate::Clear
                } else {
                    FieldUpdate::Unchanged
                }
            }
        },
    };
    let updated = crate::domain::identity::service::update_me(&*state.repos.users, user_id, &req).await?;
    Ok(axum::Json(crate::api::response::ApiResponse::success(updated)).into_response())
}

pub async fn send_verify_email_post(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let user = common::get_account_user(&state, &headers).await?;

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
        &*state.repos.kv,
        EMAIL_VERIFY_PREFIX,
        &payload,
        state.config.sso.email_verify_ttl_seconds,
    )
    .await?;
    tracing::info!(user_id = %user.id, "email verification token generated (account page)");
    Ok(axum::Json(crate::api::response::MessageResponse::success(
        "Verification email sent.",
    ))
    .into_response())
}

pub async fn send_verify_phone_post(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, AppError> {
    let user = common::get_account_user(&state, &headers).await?;
    let phone = match user.phone.clone() {
        Some(phone) => phone,
        None => return Err(AppError::BadRequest("Phone number is not set.".into())),
    };
    if user.phone_verified {
        return Err(crate::domain::identity::error::phone_already_verified());
    }

    let payload = VerifyPayload {
        user_id: user.id,
        value: phone.to_string(),
    };
    let _token = crate::shared::utils::generate_token_and_cache(
        &*state.repos.kv,
        PHONE_VERIFY_PREFIX,
        &payload,
        state.config.sso.phone_verify_ttl_seconds,
    )
    .await?;
    tracing::info!(user_id = %user.id, "phone verification token generated (account page)");
    Ok(axum::Json(crate::api::response::MessageResponse::success(
        "Verification SMS sent.",
    ))
    .into_response())
}
