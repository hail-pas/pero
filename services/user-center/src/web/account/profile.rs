use axum::extract::State;
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::cookie::CookieJar;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};

use crate::state::app::AppState;
use crate::web::account::dto::{ProfileForm, ProfileUser, ProfileView};
use crate::web::session::extract_session;

/// EP-20: GET /account/profile
pub async fn get(State(state): State<AppState>, jar: CookieJar) -> Response {
    let session = match extract_session(&state, &jar).await {
        Ok(Some(s)) => s,
        Ok(None) => return Redirect::to("/account/login").into_response(),
        Err(status) => return status.into_response(),
    };

    let user = match crate::db::entity::users::Entity::find_by_id(session.user_id)
        .one(&state.db)
        .await
    {
        Ok(Some(u)) => u,
        Ok(None) => {
            let cookies = state.cookie_factory();
            let jar = jar.add(cookies.clear_cookie(cookies.session_cookie_name()));
            return (jar, Redirect::to("/account/login")).into_response();
        }
        Err(e) => {
            tracing::error!("Profile user lookup: {e}");
            return axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response();
        }
    };

    let layout = match super::dto::AccountLayout::from_user(&state.db, &user).await {
        Ok(layout) => layout,
        Err(error) => return crate::web::util::dependency_error(error),
    };

    let (jar, csrf_token) = state.web_security().ensure_csrf(jar);

    let pending_requests = match crate::db::entity::contact_change_requests::Entity::find()
        .filter(crate::db::entity::contact_change_requests::Column::UserId.eq(user.id))
        .filter(
            crate::db::entity::contact_change_requests::Column::Status
                .eq(crate::db::enums::ContactChangeStatus::Pending),
        )
        .filter(
            crate::db::entity::contact_change_requests::Column::ExpiresAt
                .gt(time::OffsetDateTime::now_utc()),
        )
        .all(&state.db)
        .await
    {
        Ok(rows) => rows,
        Err(error) => return crate::web::util::dependency_error(error),
    };

    let (pending_email_nonce, pending_email_value) = pending_requests
        .iter()
        .find(|r| r.change_type == crate::db::enums::ContactChangeType::Email)
        .map(|r| (r.nonce.clone(), r.new_value.clone()))
        .unwrap_or_default();

    let (pending_phone_nonce, pending_phone_value) = pending_requests
        .iter()
        .find(|r| r.change_type == crate::db::enums::ContactChangeType::Phone)
        .map(|r| (r.nonce.clone(), r.new_value.clone()))
        .unwrap_or_default();

    let has_password = match crate::db::entity::identities::Entity::find()
        .filter(crate::db::entity::identities::Column::UserId.eq(user.id))
        .filter(
            crate::db::entity::identities::Column::Kind
                .eq(crate::db::enums::IdentityKind::Password),
        )
        .filter(crate::db::entity::identities::Column::UnboundAt.is_null())
        .one(&state.db)
        .await
    {
        Ok(identity) => identity.is_some(),
        Err(_) => return axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };

    let profile_user = ProfileUser {
        username: user.username,
        email: user.email.unwrap_or_default(),
        email_verified: user.email_verified_at.is_some(),
        phone: user.phone.unwrap_or_default(),
        phone_verified: user.phone_verified_at.is_some(),
        nickname: user.nickname.unwrap_or_default(),
        avatar_url: user.avatar_url.unwrap_or_default(),
        created_at: user.created_at,
        pending_email_nonce,
        pending_email_value,
        pending_phone_nonce,
        pending_phone_value,
        has_password,
    };

    let tpl = ProfileView {
        layout,
        user: profile_user,
        csrf_token,
    };
    (jar, pero_api_axum::form::view("ProfileView", tpl)).into_response()
}

/// EP-21: POST /account/profile（AJAX）
pub async fn post(
    State(state): State<AppState>,
    jar: CookieJar,
    axum::Form(form): axum::Form<ProfileForm>,
) -> Response {
    if !state.web_security().verify_csrf(&jar, &form.csrf_token) {
        return (
            axum::http::StatusCode::FORBIDDEN,
            axum::Json(serde_json::json!({"error": "invalid_csrf"})),
        )
            .into_response();
    }

    let session = match extract_session(&state, &jar).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            return axum::Json(serde_json::json!({"error": "unauthorized"})).into_response();
        }
        Err(status) => return status.into_response(),
    };

    let user = match crate::db::entity::users::Entity::find_by_id(session.user_id)
        .one(&state.db)
        .await
    {
        Ok(Some(u)) => u,
        Ok(None) => return axum::Json(serde_json::json!({"error": "not_found"})).into_response(),
        Err(error) => return crate::web::util::dependency_error(error),
    };

    let mut active: crate::db::entity::users::ActiveModel = user.into();
    active.updated_at = Set(time::OffsetDateTime::now_utc());

    if let Some(nickname) = &form.nickname {
        active.nickname = Set(if nickname.is_empty() {
            None
        } else {
            Some(nickname.clone())
        });
    }
    if let Some(avatar_url) = &form.avatar_url {
        let avatar_url = avatar_url.trim();
        if !avatar_url.is_empty() {
            match pero_utils::redirect::validate_public_http_url(avatar_url) {
                Err(pero_utils::redirect::PublicHttpUrlError::InvalidScheme) => {
                    return (
                        axum::http::StatusCode::BAD_REQUEST,
                        axum::Json(serde_json::json!({"error": "avatar_url_bad_scheme"})),
                    )
                        .into_response();
                }
                Err(_) => {
                    return (
                        axum::http::StatusCode::BAD_REQUEST,
                        axum::Json(serde_json::json!({"error": "avatar_url_invalid"})),
                    )
                        .into_response();
                }
                _ => {}
            }
        }
        active.avatar_url = Set(if avatar_url.is_empty() {
            None
        } else {
            Some(avatar_url.to_owned())
        });
    }

    if let Err(e) = active.update(&state.db).await {
        tracing::error!("Profile update: {e}");
        return (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(serde_json::json!({"error": "update_failed"})),
        )
            .into_response();
    }

    axum::Json(serde_json::json!({"code": 0, "message": "ok"})).into_response()
}
