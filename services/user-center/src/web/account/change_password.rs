use axum::extract::State;
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::cookie::CookieJar;
use pero_api_axum::{json_ok, json_ok_with_error};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};

use crate::db::enums::IdentityKind;
use crate::service::{ManagementError, account::AccountService};
use crate::state::app::AppState;
use crate::web::account::dto::{ChangePasswordForm, ChangePasswordView};
use crate::web::session::extract_session;

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

    let layout = super::dto::AccountLayout::from_user(&state.db, &user).await;
    let (jar, csrf_token) = state.web_security().ensure_csrf(jar);

    let tpl = ChangePasswordView {
        layout,
        csrf_token,
        has_password,
    };
    (jar, pero_api_axum::form::view("ChangePasswordView", tpl)).into_response()
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

    match AccountService::new(&state)
        .change_password(
            &session,
            form.old_password.as_deref(),
            &form.new_password,
            &form.confirm_password,
        )
        .await
    {
        Ok(()) => json_ok(),
        Err(ManagementError::Invalid(code)) => json_ok_with_error(code),
        Err(ManagementError::Validation(message)) => json_ok_with_error(&message),
        Err(error) => crate::web::util::dependency_error(error),
    }
}
