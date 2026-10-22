use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::cookie::CookieJar;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set, TransactionTrait};
use serde::Deserialize;

use crate::db::entity::{identities, user_app_access, users};
use crate::db::enums::{CommonStatus, IdentityKind, UserStatus};
use crate::service::password::PasswordIdentityService;
use crate::state::app::AppState;
use crate::web::dashboard::guard::{AdminContext, AdminPage};
use crate::web::dashboard::template::{
    GrantAppForm, ResetPasswordForm, RevokeAppForm, UserAccessRow, UserDetailTemplate,
    UserFormData, UserFormTemplate, UserIdentityRow, UserStatusForm,
};
use crate::web::util::{self, render_template};
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
    } = AdminPage::new(&state, jar, admin, "users");

    let page_num = query.page.unwrap_or(1).max(1);
    let q = query.q.unwrap_or_default();
    let status_filter = query.status.unwrap_or_default();

    let (users_list, total_pages) =
        crate::db::helper::admin::list_users(&state.db, page_num, &q, &status_filter)
            .await
            .unwrap_or_else(|e| {
                tracing::error!("List users: {e}");
                (vec![], 0)
            });

    let tpl = super::template::UserListTemplate {
        layout,
        csrf_token,
        users: users_list,
        page: page_num,
        total_pages,
        q,
        status_filter,
    };
    render_template(tpl, jar)
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
    } = AdminPage::new(&state, jar, admin, "users");

    let tpl = UserFormTemplate {
        layout,
        csrf_token,
        mode: "create".to_owned(),
        user_id: String::new(),
        form: UserFormData::default(),
        error: String::new(),
    };
    render_template(tpl, jar)
}

pub async fn create(
    State(state): State<AppState>,
    jar: CookieJar,
    axum::Form(form): axum::Form<UserFormData>,
) -> Response {
    if let Some(response) = util::verify_csrf_or_json_error(&jar, &form.csrf_token, &state) {
        return response;
    }

    let username = form.username.trim();
    if username.is_empty() || form.password.is_empty() {
        return json_error("username_and_password_required");
    }
    if crate::db::helper::user::validate_username(username).is_err() {
        return json_error("username_chars_invalid");
    }

    if let Err(err) = state.config.password.validate_password(&form.password) {
        return json_error(&err);
    }
    if util::validate_optional_public_url(&form.avatar_url).is_err() {
        return json_error("invalid_url");
    }

    let username_conflict = users::Entity::find()
        .filter(users::Column::Username.eq(form.username.trim()))
        .one(&state.db)
        .await
        .unwrap_or_else(|e| {
            tracing::error!("Check username: {e}");
            None
        })
        .is_some();
    if username_conflict {
        return json_error("username_exists");
    }

    let txn = match state.db.begin().await {
        Ok(t) => t,
        Err(e) => {
            tracing::error!("Begin txn: {e}");
            return json_error("internal_error");
        }
    };

    let now = time::OffsetDateTime::now_utc();
    let user_id = uuid::Uuid::now_v7();

    let user_model = users::ActiveModel {
        id: Set(user_id),
        username: Set(form.username.trim().to_owned()),
        email: Set(util::empty_or_opt(&form.email)),
        phone: Set(util::empty_or_opt(&form.phone)),
        nickname: Set(util::empty_or_opt(&form.nickname)),
        avatar_url: Set(util::empty_or_opt(&form.avatar_url)),
        status: Set(UserStatus::Active),
        created_at: Set(now),
        updated_at: Set(now),
        deleted_at: Set(None),
        email_verified_at: Set(None),
        phone_verified_at: Set(None),
    };

    let user = match user_model.insert(&txn).await {
        Ok(u) => u,
        Err(e) => {
            tracing::error!("Create user: {e}");
            let _ = txn.rollback().await;
            return json_error("create_failed");
        }
    };

    let provider = match crate::db::helper::identity_provider::find_local_provider(&txn).await {
        Ok(p) => p,
        Err(e) => {
            tracing::error!("Local provider not found: {e}");
            let _ = txn.rollback().await;
            return json_error("internal_error");
        }
    };

    if let Err(e) = PasswordIdentityService::create(
        &txn,
        user.id,
        provider.id,
        user.username.clone(),
        &form.password,
        now,
    )
    .await
    {
        tracing::error!("Create identity: {e}");
        let _ = txn.rollback().await;
        return json_error("create_failed");
    }

    if let Err(e) = txn.commit().await {
        tracing::error!("Commit: {e}");
        return json_error("internal_error");
    }

    json_ok()
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
    } = AdminPage::new(&state, jar, admin, "users");
    let user = match crate::db::helper::admin::find_user_by_id(&state.db, id).await {
        Ok(Some(u)) if u.deleted_at.is_none() => u,
        _ => return Redirect::to("/dashboard/users").into_response(),
    };

    let identity_rows = crate::db::helper::admin::list_user_identities(&state.db, user.id)
        .await
        .unwrap_or_else(|e| {
            tracing::error!("List identities: {e}");
            vec![]
        });

    let providers: std::collections::HashMap<uuid::Uuid, (String, String)> =
        crate::db::entity::identity_providers::Entity::find()
            .all(&state.db)
            .await
            .unwrap_or_else(|e| {
                tracing::error!("List providers: {e}");
                vec![]
            })
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
                kind: i.kind,
                provider_name,
                provider_code,
                last_login_at: i.last_login_at.map(|t| t.to_string()),
            }
        })
        .collect();

    let access_rows = crate::db::helper::admin::list_user_access(&state.db, user.id)
        .await
        .unwrap_or_else(|e| {
            tracing::error!("List user access: {e}");
            vec![]
        });
    let access_list = access_rows
        .into_iter()
        .map(|(a, app)| UserAccessRow {
            app_id: a.app_id,
            app_code: app.code,
            app_name: app.name,
            status: a.status,
        })
        .collect();

    let all_apps = crate::db::helper::admin::list_all_apps_brief(&state.db)
        .await
        .unwrap_or_else(|e| {
            tracing::error!("List apps: {e}");
            vec![]
        });

    let tpl = UserDetailTemplate {
        layout,
        csrf_token,
        user,
        identities,
        access_list,
        all_apps,
        error: String::new(),
    };
    render_template(tpl, jar)
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
    } = AdminPage::new(&state, jar, admin, "users");
    let user = match crate::db::helper::admin::find_user_by_id(&state.db, id).await {
        Ok(Some(u)) if u.deleted_at.is_none() => u,
        _ => return Redirect::to("/dashboard/users").into_response(),
    };

    let tpl = UserFormTemplate {
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
            password: String::new(),
        },
        error: String::new(),
    };
    render_template(tpl, jar)
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

    if form.new_password.is_empty() {
        return json_error("password_required");
    }
    if let Err(err) = state.config.password.validate_password(&form.new_password) {
        return json_error(&err);
    }

    let user = match crate::db::helper::admin::find_user_by_id(&state.db, id).await {
        Ok(Some(u)) if u.deleted_at.is_none() => u,
        _ => return json_error("not_found"),
    };

    let password_hash = match PasswordIdentityService::hash_password(&form.new_password).await {
        Ok(hash) => hash,
        Err(_) => return json_error("service_unavailable"),
    };

    let txn = match state.db.begin().await {
        Ok(txn) => txn,
        Err(e) => {
            tracing::error!("Admin reset password transaction begin: {e}");
            return json_error("internal_error");
        }
    };

    if PasswordIdentityService::lock_user(&txn, user.id)
        .await
        .is_err()
    {
        return json_error("internal_error");
    }

    let identity = match identities::Entity::find()
        .filter(identities::Column::UserId.eq(user.id))
        .filter(identities::Column::Kind.eq(IdentityKind::Password))
        .filter(identities::Column::UnboundAt.is_null())
        .one(&txn)
        .await
    {
        Ok(value) => value,
        Err(_) => return json_error("internal_error"),
    };

    let Some(id_model) = identity else {
        return json_error("no_password_identity");
    };

    let now = time::OffsetDateTime::now_utc();

    match PasswordIdentityService::update_hashed(&txn, id_model, password_hash, now).await {
        Ok(_) => {}
        Err(e) => {
            tracing::error!("Reset password: {e}");
            return json_error("update_failed");
        }
    }

    if let Err(e) = crate::service::session::SessionService::revoke_all_login_state_for_user_in_db(
        &txn,
        user.id,
        "admin_password_reset",
    )
    .await
    {
        tracing::error!("Session revoke during admin password reset: {e}");
        return json_error("session_revoke_failed");
    }

    if let Err(e) = txn.commit().await {
        tracing::error!("Admin reset password transaction commit: {e}");
        return json_error("internal_error");
    }

    json_ok()
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

    let _user = match crate::db::helper::admin::find_user_by_id(&state.db, id).await {
        Ok(Some(u)) if u.deleted_at.is_none() => u,
        _ => return json_error("not_found"),
    };

    let app_id = match uuid::Uuid::parse_str(&form.app_id) {
        Ok(id) => id,
        Err(_) => return json_error("invalid_app_id"),
    };

    let now = time::OffsetDateTime::now_utc();

    let existing = user_app_access::Entity::find()
        .filter(user_app_access::Column::UserId.eq(id))
        .filter(user_app_access::Column::AppId.eq(app_id))
        .one(&state.db)
        .await;

    match existing {
        Ok(Some(access)) => {
            let mut active: user_app_access::ActiveModel = access.into();
            active.status = Set(CommonStatus::Active);
            active.updated_at = Set(now);
            match active.update(&state.db).await {
                Ok(_) => json_ok(),
                Err(e) => {
                    tracing::error!("Grant app (update): {e}");
                    json_error("grant_failed")
                }
            }
        }
        Ok(None) => {
            let access = user_app_access::ActiveModel {
                user_id: Set(id),
                app_id: Set(app_id),
                status: Set(CommonStatus::Active),
                created_at: Set(now),
                updated_at: Set(now),
            };
            match access.insert(&state.db).await {
                Ok(_) => json_ok(),
                Err(e) => {
                    tracing::error!("Grant app: {e}");
                    json_error("grant_failed")
                }
            }
        }
        Err(e) => {
            tracing::error!("Check access: {e}");
            json_error("grant_failed")
        }
    }
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

    let _user = match crate::db::helper::admin::find_user_by_id(&state.db, id).await {
        Ok(Some(u)) if u.deleted_at.is_none() => u,
        _ => return json_error("not_found"),
    };

    let app_id = match uuid::Uuid::parse_str(&form.app_id) {
        Ok(id) => id,
        Err(_) => return json_error("invalid_app_id"),
    };

    let existing = user_app_access::Entity::find()
        .filter(user_app_access::Column::UserId.eq(id))
        .filter(user_app_access::Column::AppId.eq(app_id))
        .one(&state.db)
        .await;

    match existing {
        Ok(Some(access)) => {
            let mut active: user_app_access::ActiveModel = access.into();
            active.status = Set(CommonStatus::Disabled);
            active.updated_at = Set(time::OffsetDateTime::now_utc());
            let result: Result<(), sea_orm::DbErr> = async {
                let txn = state.db.begin().await?;
                let updated = active.update(&txn).await?;
                crate::service::session::SessionService::revoke_app_grants(
                    &txn,
                    updated.app_id,
                    Some(updated.user_id),
                    "app_access_revoked",
                )
                .await?;
                txn.commit().await
            }
            .await;
            match result {
                Ok(()) => json_ok(),
                Err(e) => {
                    tracing::error!("Revoke app: {e}");
                    json_error("revoke_failed")
                }
            }
        }
        Ok(None) => json_ok(),
        Err(e) => {
            tracing::error!("Check access: {e}");
            json_error("revoke_failed")
        }
    }
}
