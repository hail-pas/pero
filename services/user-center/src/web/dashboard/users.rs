use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::cookie::CookieJar;
use sea_orm::EntityTrait;
use serde::Deserialize;

use crate::db::enums::UserStatus;
use crate::state::app::AppState;
use crate::web::dashboard::dto::{
    GrantAppForm, ResetPasswordForm, RevokeAppForm, UserAccessRow, UserDetailView, UserFormData,
    UserFormView, UserIdentityRow, UserStatusForm,
};
use crate::web::dashboard::guard::{AdminContext, AdminPage};
use crate::web::util::{self, view_response};
use pero_api_axum::{json_error, json_ok};

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    pub q: Option<String>,
    pub status: Option<String>,
    pub page: Option<u64>,
}

pub async fn list(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(query): Query<ListQuery>,
    admin: AdminContext,
) -> Response {
    let AdminPage {
        layout,
        csrf_token,
        jar,
        ..
    } = AdminPage::new(&state, jar, admin);

    let page_num = query.page.unwrap_or(1).max(1);
    let q = query.q.unwrap_or_default();
    let status_filter = query.status.unwrap_or_default();

    let (users_list, total_pages) =
        match crate::db::helper::admin::list_users(&state.db, page_num, &q, &status_filter).await {
            Ok(data) => data,
            Err(error) => return util::dependency_error(error),
        };

    let tpl = super::dto::UserListView {
        layout,
        csrf_token,
        users: users_list.into_iter().map(Into::into).collect(),
        page: page_num,
        total_pages,
        q,
        status_filter,
    };
    view_response("UserListView", tpl, jar)
}

pub async fn new_form(
    State(state): State<AppState>,
    jar: CookieJar,
    admin: AdminContext,
) -> Response {
    let AdminPage {
        layout,
        csrf_token,
        jar,
        ..
    } = AdminPage::new(&state, jar, admin);

    let tpl = UserFormView {
        layout,
        csrf_token,
        mode: "create".to_owned(),
        user_id: String::new(),
        form: UserFormData::default(),
        error: String::new(),
    };
    view_response("UserFormView", tpl, jar)
}

pub async fn create(
    State(state): State<AppState>,
    jar: CookieJar,
    admin: AdminContext,
    axum::Form(form): axum::Form<UserFormData>,
) -> Response {
    if let Some(response) = util::verify_csrf_or_json_error(&jar, &form.csrf_token, &state) {
        return response;
    }

    util::management_response(
        crate::service::enrollment::start(
            &state,
            &form.email,
            None,
            Some((&admin.session, false, "")),
        )
        .await,
    )
}

pub async fn detail(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<uuid::Uuid>,
    admin: AdminContext,
) -> Response {
    let AdminPage {
        layout,
        csrf_token,
        jar,
        ..
    } = AdminPage::new(&state, jar, admin);
    let user = match crate::db::helper::admin::find_user_by_id(&state.db, id).await {
        Ok(Some(u)) if u.deleted_at.is_none() => u,
        Err(error) => return util::dependency_error(error),
        _ => return Redirect::to("/dashboard/users").into_response(),
    };

    let identity_rows =
        match crate::db::helper::admin::list_user_identities(&state.db, user.id).await {
            Ok(data) => data,
            Err(error) => return util::dependency_error(error),
        };

    let providers: std::collections::HashMap<uuid::Uuid, (String, String)> =
        match crate::db::entity::identity_providers::Entity::find()
            .all(&state.db)
            .await
        {
            Ok(data) => data,
            Err(error) => return util::dependency_error(error),
        }
        .into_iter()
        .map(|p| (p.id, (p.name, p.code)))
        .collect();

    let identities = identity_rows
        .into_iter()
        .map(|i| {
            let (provider_name, provider_code) = providers
                .get(&i.provider_id)
                .cloned()
                .unwrap_or_else(|| ("Unknown".to_owned(), "unknown".to_owned()));
            UserIdentityRow {
                id: i.id,
                kind: i.kind.to_string(),
                provider_name,
                provider_code,
                last_login_at: i.last_login_at,
            }
        })
        .collect();

    let access_rows = match crate::db::helper::admin::list_user_access(&state.db, user.id).await {
        Ok(data) => data,
        Err(error) => return util::dependency_error(error),
    };
    let access_list = access_rows
        .into_iter()
        .map(|(a, app)| UserAccessRow {
            app_id: a.app_id,
            app_code: app.code,
            app_name: app.name,
            status: a.status.to_string(),
        })
        .collect();

    let all_apps = match crate::db::helper::admin::list_all_apps_brief(&state.db).await {
        Ok(data) => data,
        Err(error) => return util::dependency_error(error),
    };

    let tpl = UserDetailView {
        layout,
        csrf_token,
        user: user.into(),
        identities,
        access_list,
        all_apps,
        error: String::new(),
    };
    view_response("UserDetailView", tpl, jar)
}

pub async fn edit_form(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<uuid::Uuid>,
    admin: AdminContext,
) -> Response {
    let AdminPage {
        layout,
        csrf_token,
        jar,
        ..
    } = AdminPage::new(&state, jar, admin);
    let user = match crate::db::helper::admin::find_user_by_id(&state.db, id).await {
        Ok(Some(u)) if u.deleted_at.is_none() => u,
        Err(error) => return util::dependency_error(error),
        _ => return Redirect::to("/dashboard/users").into_response(),
    };

    let tpl = UserFormView {
        layout,
        csrf_token,
        mode: "edit".to_owned(),
        user_id: user.id.to_string(),
        form: UserFormData {
            csrf_token: String::new(),
            username: user.username.clone(),
            email: user.email.unwrap_or_default(),
            phone: user.phone.unwrap_or_default(),
            nickname: user.nickname.unwrap_or_default(),
            avatar_url: user.avatar_url.unwrap_or_default(),
        },
        error: String::new(),
    };
    view_response("UserFormView", tpl, jar)
}

pub async fn update(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<uuid::Uuid>,
    axum::Form(form): axum::Form<UserFormData>,
) -> Response {
    if let Some(response) = util::verify_csrf_or_json_error(&jar, &form.csrf_token, &state) {
        return response;
    }
    util::management_response(
        crate::service::user::update(
            &state.db,
            id,
            crate::service::user::UserUpdate {
                email: util::empty_or_opt(&form.email),
                phone: util::empty_or_opt(&form.phone),
                nickname: util::empty_or_opt(&form.nickname),
                avatar_url: util::empty_or_opt(&form.avatar_url),
            },
        )
        .await,
    )
}

pub async fn set_status(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<uuid::Uuid>,
    admin: AdminContext,
    axum::Form(form): axum::Form<UserStatusForm>,
) -> Response {
    if let Some(response) = util::verify_csrf_or_json_error(&jar, &form.csrf_token, &state) {
        return response;
    }
    let status = match UserStatus::try_from_str(&form.status) {
        Ok(value) => value,
        Err(_) => return json_error("invalid_status"),
    };
    match crate::service::user::set_status(&state.db, id, admin.session.user_id, status).await {
        Ok(()) => json_ok(),
        Err(error) => util::management_response(Err(error)),
    }
}

pub async fn reset_password(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<uuid::Uuid>,
    axum::Form(form): axum::Form<ResetPasswordForm>,
) -> Response {
    if let Some(response) = util::verify_csrf_or_json_error(&jar, &form.csrf_token, &state) {
        return response;
    }

    util::management_response(
        crate::service::user::reset_password(
            &state.db,
            &state.config.password,
            id,
            &form.new_password,
        )
        .await,
    )
}

pub async fn grant_app(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<uuid::Uuid>,
    axum::Form(form): axum::Form<GrantAppForm>,
) -> Response {
    if let Some(response) = util::verify_csrf_or_json_error(&jar, &form.csrf_token, &state) {
        return response;
    }
    let app_id = match uuid::Uuid::parse_str(&form.app_id) {
        Ok(id) => id,
        Err(_) => return json_error("invalid_app_id"),
    };
    util::management_response(crate::service::access::grant_app(&state.db, id, app_id).await)
}

pub async fn revoke_app(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<uuid::Uuid>,
    axum::Form(form): axum::Form<RevokeAppForm>,
) -> Response {
    if let Some(response) = util::verify_csrf_or_json_error(&jar, &form.csrf_token, &state) {
        return response;
    }
    let app_id = match uuid::Uuid::parse_str(&form.app_id) {
        Ok(id) => id,
        Err(_) => return json_error("invalid_app_id"),
    };
    util::management_response(crate::service::access::revoke_app(&state.db, id, app_id).await)
}
