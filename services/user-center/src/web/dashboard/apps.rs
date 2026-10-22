use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::cookie::CookieJar;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
use serde::Deserialize;

use crate::db::entity::{apps, oauth_clients};
use crate::db::enums::{AppType, CommonStatus, OauthClientType};
use crate::state::app::AppState;
use crate::web::dashboard::guard::{AdminContext, AdminPage};
use crate::web::dashboard::template::{
    AppDetailTemplate, AppFormData, AppFormTemplate, AppListTemplate, ClientForm,
};
use crate::web::util::{self, CsrfOnly, render_template};
use pero_api_axum::{json_error, json_ok, json_ok_with_sensitive};

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    pub q: Option<String>,
    pub status: Option<String>,
    pub app_type: Option<String>,
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
    } = AdminPage::new(&state, jar, admin, "apps");

    let page_num = query.page.unwrap_or(1).max(1);
    let q = query.q.unwrap_or_default();
    let status_filter = query.status.unwrap_or_default();
    let type_filter = query.app_type.unwrap_or_default();

    let (apps_list, total_pages) =
        crate::db::helper::admin::list_apps(&state.db, page_num, &q, &status_filter, &type_filter)
            .await
            .unwrap_or_else(|e| {
                tracing::error!("List apps: {e}");
                (vec![], 0)
            });

    let tpl = AppListTemplate {
        layout,
        csrf_token,
        apps: apps_list,
        page: page_num,
        total_pages,
        q,
        status_filter,
        type_filter,
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
    } = AdminPage::new(&state, jar, admin, "apps");

    let tpl = AppFormTemplate {
        layout,
        csrf_token,
        mode: "create".to_owned(),
        app_id: String::new(),
        form: AppFormData::default(),
        error: String::new(),
    };
    render_template(tpl, jar)
}

pub async fn create(
    State(state): State<AppState>,
    jar: CookieJar,
    axum::Form(form): axum::Form<AppFormData>,
) -> Response {
    if let Some(response) = util::verify_csrf_or_json_error(&jar, &form.csrf_token, &state) {
        return response;
    }

    if form.code.trim().is_empty() || form.name.trim().is_empty() {
        return json_error("code_and_name_required");
    }

    let code_conflict = match apps::Entity::find()
        .filter(apps::Column::Code.eq(form.code.trim()))
        .one(&state.db)
        .await
    {
        Ok(row) => row.is_some(),
        Err(e) => {
            tracing::error!("Check code conflict: {e}");
            return json_error("internal_error");
        }
    };
    if code_conflict {
        return json_error("code_exists");
    }
    if util::validate_optional_public_url(&form.homepage_url).is_err()
        || util::validate_optional_public_url(&form.logo_url).is_err()
    {
        return json_error("invalid_url");
    }

    let now = time::OffsetDateTime::now_utc();
    let model = apps::ActiveModel {
        id: Set(uuid::Uuid::now_v7()),
        code: Set(form.code.trim().to_owned()),
        name: Set(form.name.trim().to_owned()),
        r#type: Set(match AppType::try_from_str(form.app_type.as_str()) {
            Ok(value) => value,
            Err(_) => return json_error("invalid_app_type"),
        }),
        description: Set(util::empty_or_opt(&form.description)),
        homepage_url: Set(util::empty_or_opt(&form.homepage_url)),
        logo_url: Set(util::empty_or_opt(&form.logo_url)),
        auto_access: Set(form.auto_access.is_some()),
        system: Set(false),
        status: Set(CommonStatus::Active),
        created_at: Set(now),
        updated_at: Set(now),
    };

    match model.insert(&state.db).await {
        Ok(_) => json_ok(),
        Err(e) => {
            tracing::error!("Create app: {e}");
            json_error("create_failed")
        }
    }
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
    } = AdminPage::new(&state, jar, admin, "apps");
    let app = match crate::db::helper::admin::find_app_by_id(&state.db, id).await {
        Ok(Some(a)) => a,
        _ => return Redirect::to("/dashboard/apps").into_response(),
    };

    let clients = crate::db::helper::admin::list_clients_by_app(&state.db, id)
        .await
        .unwrap_or_else(|e| {
            tracing::error!("List clients: {e}");
            vec![]
        });

    let tpl = AppDetailTemplate {
        layout,
        csrf_token,
        app,
        clients,
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
    } = AdminPage::new(&state, jar, admin, "apps");
    let app = match crate::db::helper::admin::find_app_by_id(&state.db, id).await {
        Ok(Some(a)) => a,
        _ => return Redirect::to("/dashboard/apps").into_response(),
    };
    if app.system {
        return Redirect::to(&format!("/dashboard/apps/{}", app.id)).into_response();
    }

    let tpl = AppFormTemplate {
        layout,
        csrf_token,
        mode: "edit".to_owned(),
        app_id: app.id.to_string(),
        form: AppFormData {
            csrf_token: String::new(),
            code: app.code.clone(),
            name: app.name.clone(),
            app_type: app.r#type.to_string(),
            description: app.description.unwrap_or_default(),
            homepage_url: app.homepage_url.unwrap_or_default(),
            logo_url: app.logo_url.unwrap_or_default(),
            auto_access: if app.auto_access {
                Some("on".to_owned())
            } else {
                None
            },
        },
        error: String::new(),
    };
    render_template(tpl, jar)
}

pub async fn update(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<uuid::Uuid>,
    axum::Form(form): axum::Form<AppFormData>,
) -> Response {
    if let Some(response) = util::verify_csrf_or_json_error(&jar, &form.csrf_token, &state) {
        return response;
    }
    let app_type = match AppType::try_from_str(&form.app_type) {
        Ok(value) => value,
        Err(_) => return json_error("invalid_app_type"),
    };
    util::management_response(
        crate::service::app::update(
            &state.db,
            id,
            crate::service::app::AppUpdate {
                name: form.name.trim().to_owned(),
                app_type,
                description: util::empty_or_opt(&form.description),
                homepage_url: util::empty_or_opt(&form.homepage_url),
                logo_url: util::empty_or_opt(&form.logo_url),
                auto_access: form.auto_access.is_some(),
            },
        )
        .await,
    )
}

pub async fn toggle_status(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<uuid::Uuid>,
    axum::Form(form): axum::Form<CsrfOnly>,
) -> Response {
    if let Some(response) = util::verify_csrf_or_json_error(&jar, &form.csrf_token, &state) {
        return response;
    }
    util::management_response(crate::service::app::toggle_status(&state.db, id).await)
}

pub async fn create_client(
    State(state): State<AppState>,
    jar: CookieJar,
    axum::Form(form): axum::Form<ClientForm>,
) -> Response {
    if let Some(response) = util::verify_csrf_or_json_error(&jar, &form.csrf_token, &state) {
        return response;
    }

    if form.identifier.trim().is_empty() {
        return json_error("identifier_required");
    }

    let app_id = match uuid::Uuid::parse_str(&form.app_id) {
        Ok(id) => id,
        Err(_) => return json_error("invalid_app"),
    };

    match apps::Entity::find_by_id(app_id).one(&state.db).await {
        Ok(Some(_)) => {}
        Ok(None) => return json_error("invalid_app"),
        Err(_) => return json_error("internal_error"),
    }

    let identifier_conflict = oauth_clients::Entity::find()
        .filter(oauth_clients::Column::Identifier.eq(form.identifier.trim()))
        .one(&state.db)
        .await
        .unwrap_or_else(|e| {
            tracing::error!("Check identifier conflict: {e}");
            None
        })
        .is_some();
    if identifier_conflict {
        return json_error("identifier_exists");
    }

    let client_type = match OauthClientType::try_from_str(form.client_type.as_str()) {
        Ok(value) => value,
        Err(_) => return json_error("invalid_client_type"),
    };

    let raw_secret = if client_type == OauthClientType::Confidential {
        let s = if form.secret.trim().is_empty() {
            pero_utils::crypto::generate_token()
        } else {
            form.secret.trim().to_owned()
        };
        Some(s)
    } else {
        None
    };

    let secret_hash = match raw_secret {
        Some(ref s) => match pero_utils::crypto::hash_secret_async(s).await {
            Ok(h) => Some(h),
            Err(e) => {
                tracing::error!("Hash secret: {e}");
                return json_error("internal_error");
            }
        },
        None => None,
    };

    let redirect_uris = util::parse_lines(&form.redirect_uris);
    if let Err(e) = util::validate_redirect_uris(&redirect_uris) {
        return json_error(e);
    }
    let post_logout_redirect_uris = util::parse_lines(&form.post_logout_redirect_uris);
    if let Err(e) = util::validate_redirect_uris(&post_logout_redirect_uris) {
        return json_error(e);
    }

    let now = time::OffsetDateTime::now_utc();
    let model = oauth_clients::ActiveModel {
        id: Set(uuid::Uuid::now_v7()),
        app_id: Set(app_id),
        identifier: Set(form.identifier.trim().to_owned()),
        secret_hash: Set(secret_hash),
        name: Set(util::empty_or_opt(&form.name)),
        r#type: Set(client_type),
        redirect_uris: Set(redirect_uris),
        post_logout_redirect_uris: Set(post_logout_redirect_uris),
        scopes: Set(util::parse_comma_list(&form.scopes)),
        grant_types: Set(util::parse_comma_list(&form.grant_types)),
        require_pkce: Set(form.require_pkce.is_some()),
        access_token_ttl_seconds: Set(form.access_token_ttl.max(60)),
        refresh_token_ttl_seconds: Set(form.refresh_token_ttl.max(60)),
        id_token_ttl_seconds: Set(form.id_token_ttl.max(60)),
        status: Set(CommonStatus::Active),
        created_at: Set(now),
        updated_at: Set(now),
    };

    match model.insert(&state.db).await {
        Ok(_) => {
            if let Some(secret) = raw_secret {
                json_ok_with_sensitive(serde_json::json!({"secret": secret}))
            } else {
                json_ok()
            }
        }
        Err(e) => {
            tracing::error!("Create client: {e}");
            json_error("create_failed")
        }
    }
}

pub async fn update_client(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<uuid::Uuid>,
    axum::Form(form): axum::Form<ClientForm>,
) -> Response {
    if let Some(response) = util::verify_csrf_or_json_error(&jar, &form.csrf_token, &state) {
        return response;
    }
    let client = match oauth_clients::Entity::find_by_id(id).one(&state.db).await {
        Ok(Some(c)) => c,
        _ => return json_error("not_found"),
    };

    let client_type = match OauthClientType::try_from_str(form.client_type.as_str()) {
        Ok(value) => value,
        Err(_) => return json_error("invalid_client_type"),
    };
    let is_public = client_type == OauthClientType::Public;
    let type_changed = client.r#type != client_type;
    let secret_changed = !form.secret.trim().is_empty();
    if type_changed && !is_public && client.secret_hash.is_none() && !secret_changed {
        return json_error("secret_required");
    }
    let scopes = util::parse_comma_list(&form.scopes);
    let grant_types = util::parse_comma_list(&form.grant_types);
    let scopes_changed = !(crate::service::scope::allowed(&client.scopes, &scopes)
        && crate::service::scope::allowed(&scopes, &client.scopes));
    let grant_types_changed = !same_ci_set(&client.grant_types, &grant_types);

    let redirects_changed = client.redirect_uris != util::parse_lines(&form.redirect_uris);
    let pkce_changed = client.require_pkce != form.require_pkce.is_some();
    let mut active: oauth_clients::ActiveModel = client.clone().into();
    active.r#type = Set(client_type);
    if is_public {
        active.secret_hash = Set(None);
    } else if secret_changed {
        match pero_utils::crypto::hash_secret_async(form.secret.trim()).await {
            Ok(h) => active.secret_hash = Set(Some(h)),
            Err(e) => {
                tracing::error!("Hash secret: {e}");
                return json_error("internal_error");
            }
        }
    }
    active.name = Set(util::empty_or_opt(&form.name));
    let redirect_uris = util::parse_lines(&form.redirect_uris);
    if let Err(e) = util::validate_redirect_uris(&redirect_uris) {
        return json_error(e);
    }
    let post_logout_redirect_uris = util::parse_lines(&form.post_logout_redirect_uris);
    if let Err(e) = util::validate_redirect_uris(&post_logout_redirect_uris) {
        return json_error(e);
    }
    active.redirect_uris = Set(redirect_uris);
    active.post_logout_redirect_uris = Set(post_logout_redirect_uris);
    active.scopes = Set(scopes);
    active.grant_types = Set(grant_types);
    active.require_pkce = Set(form.require_pkce.is_some());
    active.access_token_ttl_seconds = Set(form.access_token_ttl.max(60));
    active.refresh_token_ttl_seconds = Set(form.refresh_token_ttl.max(60));
    active.id_token_ttl_seconds = Set(form.id_token_ttl.max(60));
    active.updated_at = Set(time::OffsetDateTime::now_utc());

    let changed = type_changed
        || secret_changed
        || scopes_changed
        || grant_types_changed
        || redirects_changed
        || pkce_changed;
    match crate::service::client::save_security_change(
        &state.db,
        &client,
        active,
        changed.then_some("client_security_changed"),
    )
    .await
    {
        Ok(()) => json_ok(),
        Err(e) => {
            tracing::error!("Update client: {e}");
            json_error("update_failed")
        }
    }
}

fn same_ci_set(left: &[String], right: &[String]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .all(|item| right.iter().any(|other| other.eq_ignore_ascii_case(item)))
}

pub async fn reset_client_secret(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<uuid::Uuid>,
    axum::Form(form): axum::Form<CsrfOnly>,
) -> Response {
    if let Some(response) = util::verify_csrf_or_json_error(&jar, &form.csrf_token, &state) {
        return response;
    }
    let client = match oauth_clients::Entity::find_by_id(id).one(&state.db).await {
        Ok(Some(c)) => c,
        _ => return json_error("not_found"),
    };

    let new_secret = pero_utils::crypto::generate_token();
    let hash = match pero_utils::crypto::hash_secret_async(&new_secret).await {
        Ok(h) => h,
        Err(e) => {
            tracing::error!("Hash secret: {e}");
            return json_error("internal_error");
        }
    };

    let mut active: oauth_clients::ActiveModel = client.clone().into();
    active.secret_hash = Set(Some(hash));
    active.updated_at = Set(time::OffsetDateTime::now_utc());

    match crate::service::client::save_security_change(
        &state.db,
        &client,
        active,
        Some("client_secret_reset"),
    )
    .await
    {
        Ok(()) => json_ok_with_sensitive(serde_json::json!({"secret": new_secret})),
        Err(e) => {
            tracing::error!("Reset client secret: {e}");
            json_error("update_failed")
        }
    }
}

pub async fn toggle_client_status(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<uuid::Uuid>,
    axum::Form(form): axum::Form<CsrfOnly>,
) -> Response {
    if let Some(response) = util::verify_csrf_or_json_error(&jar, &form.csrf_token, &state) {
        return response;
    }
    let client = match oauth_clients::Entity::find_by_id(id).one(&state.db).await {
        Ok(Some(c)) => c,
        _ => return json_error("not_found"),
    };

    let new_status = match client.status {
        CommonStatus::Active => CommonStatus::Disabled,
        CommonStatus::Disabled => CommonStatus::Active,
    };

    let mut active: oauth_clients::ActiveModel = client.clone().into();
    active.status = Set(new_status);
    active.updated_at = Set(time::OffsetDateTime::now_utc());

    match crate::service::client::save_security_change(
        &state.db,
        &client,
        active,
        Some("client_status_changed"),
    )
    .await
    {
        Ok(()) => json_ok(),
        Err(e) => {
            tracing::error!("Toggle client: {e}");
            json_error("update_failed")
        }
    }
}
