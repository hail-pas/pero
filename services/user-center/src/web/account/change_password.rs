use askama::Template;
use axum::extract::State;
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::cookie::CookieJar;
use pero_api_axum::{json_ok, json_ok_with_error};
use pero_cache_redis::rate_limit_key::rl_change_password;
use pero_cache_redis::{RateLimitError, enforce_rate_limit};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, TransactionTrait};

use crate::db::enums::IdentityKind;
use crate::service::password::PasswordIdentityService;
use crate::state::app::AppState;
use crate::web::account::template::{ChangePasswordForm, ChangePasswordTemplate};
use crate::web::session::extract_session;

use super::profile::build_layout;

/// EP-22: GET /account/change-password
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
        Ok(None) => return Redirect::to("/account/login").into_response(),
        Err(_) => return axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };

    let has_password = match crate::db::entity::identities::Entity::find()
        .filter(crate::db::entity::identities::Column::UserId.eq(session.user_id))
        .filter(crate::db::entity::identities::Column::Kind.eq(IdentityKind::Password))
        .filter(crate::db::entity::identities::Column::UnboundAt.is_null())
        .one(&state.db)
        .await
    {
        Ok(identity) => identity.is_some(),
        Err(_) => return axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };

    let layout = build_layout(&state.db, &user, "change_password").await;
    let (jar, csrf_token) = state.web_security().ensure_csrf(jar);

    let tpl = ChangePasswordTemplate {
        layout,
        csrf_token,
        has_password,
    };
    match tpl.render() {
        Ok(html) => (jar, axum::response::Html(html)).into_response(),
        Err(e) => {
            tracing::error!("Template: {e}");
            axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// EP-23: POST /account/change-password（AJAX）
pub async fn post(
    State(state): State<AppState>,
    jar: CookieJar,
    axum::Form(form): axum::Form<ChangePasswordForm>,
) -> Response {
    if !state.web_security().verify_csrf(&jar, &form.csrf_token) {
        return json_ok_with_error("invalid_csrf");
    }

    let session = match extract_session(&state, &jar).await {
        Ok(Some(s)) => s,
        Ok(None) => return json_ok_with_error("unauthorized"),
        Err(status) => return status.into_response(),
    };

    if let Ok(key) = rl_change_password.key(&session.user_id.to_string()) {
        match enforce_rate_limit(&state.cache, &key, 5).await {
            Ok(()) => {}
            Err(RateLimitError::Denied { .. }) => {
                return json_ok_with_error("rate_limited");
            }
            Err(RateLimitError::Redis(e)) => {
                tracing::error!(error = %e, "rate_limit_check redis error");
                return json_ok_with_error("service_unavailable");
            }
        }
    }

    if form.new_password != form.confirm_password {
        return json_ok_with_error("password_mismatch");
    }

    if let Err(e) = state.config.password.validate_password(&form.new_password) {
        return json_ok_with_error(&e);
    }

    let verified = match crate::db::entity::identities::Entity::find()
        .filter(crate::db::entity::identities::Column::UserId.eq(session.user_id))
        .filter(crate::db::entity::identities::Column::Kind.eq(IdentityKind::Password))
        .filter(crate::db::entity::identities::Column::UnboundAt.is_null())
        .one(&state.db)
        .await
    {
        Ok(identity) => identity,
        Err(_) => return json_ok_with_error("service_unavailable"),
    };
    if let Some(identity) = &verified {
        match PasswordIdentityService::verify_password_hash(
            form.old_password.as_deref().unwrap_or_default(),
            identity.password_hash.as_deref(),
        )
        .await
        {
            Ok(true) => {}
            Ok(false) => return json_ok_with_error("invalid_credentials"),
            Err(_) => return json_ok_with_error("service_unavailable"),
        }
    }
    let password_hash = match PasswordIdentityService::hash_password(&form.new_password).await {
        Ok(hash) => hash,
        Err(_) => return json_ok_with_error("service_unavailable"),
    };

    let txn = match state.db.begin().await {
        Ok(txn) => txn,
        Err(e) => {
            tracing::error!("Change password transaction begin error: {e}");
            return json_ok_with_error("internal_error");
        }
    };

    if PasswordIdentityService::lock_user(&txn, session.user_id)
        .await
        .is_err()
    {
        return json_ok_with_error("internal_error");
    }

    if !matches!(
        crate::db::helper::session::active_query(
            time::OffsetDateTime::now_utc(),
            state.config.sso.session_idle_ttl_seconds
        )
        .filter(crate::db::entity::sso_sessions::Column::Id.eq(session.id))
        .one(&txn)
        .await,
        Ok(Some(_))
    ) {
        return json_ok_with_error("unauthorized");
    }
    if let Some(verified) = &verified
        && PasswordIdentityService::ensure_unchanged(&txn, verified)
            .await
            .is_err()
    {
        return json_ok_with_error("invalid_credentials");
    }
    let existing = crate::db::entity::identities::Entity::find()
        .filter(crate::db::entity::identities::Column::UserId.eq(session.user_id))
        .filter(crate::db::entity::identities::Column::Kind.eq(IdentityKind::Password))
        .filter(crate::db::entity::identities::Column::UnboundAt.is_null())
        .one(&txn)
        .await;

    let now = time::OffsetDateTime::now_utc();

    match existing {
        Ok(Some(identity)) => {
            if verified.is_none() {
                return json_ok_with_error("invalid_credentials");
            }
            if let Err(e) =
                PasswordIdentityService::update_hashed(&txn, identity, password_hash, now).await
            {
                tracing::error!("Update: {e}");
                return json_ok_with_error("update_failed");
            }
        }
        Ok(None) => {
            let provider =
                match crate::db::helper::identity_provider::find_local_provider(&txn).await {
                    Ok(p) => p,
                    Err(e) => {
                        tracing::error!("Local provider not found: {e}");
                        return json_ok_with_error("internal_error");
                    }
                };
            if let Err(e) = PasswordIdentityService::create_hashed(
                &txn,
                session.user_id,
                provider.id,
                session.user_id.to_string(),
                password_hash,
                now,
            )
            .await
            {
                tracing::error!("Insert identity: {e}");
                return json_ok_with_error("internal_error");
            }
        }
        Err(e) => {
            tracing::error!("Find identity: {e}");
            return json_ok_with_error("internal_error");
        }
    }

    if let Err(e) = crate::service::session::SessionService::revoke_all_login_state_for_user_in_db(
        &txn,
        session.user_id,
        "password_change",
    )
    .await
    {
        tracing::error!("Session revoke error during password change: {e}");
        return json_ok_with_error("session_revoke_failed");
    }

    if let Err(e) = txn.commit().await {
        tracing::error!("Change password transaction commit error: {e}");
        return json_ok_with_error("internal_error");
    }

    json_ok()
}
