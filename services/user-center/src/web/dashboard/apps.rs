use crate::service::permissions::Permission as P;
use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::cookie::CookieJar;
use serde::Deserialize;

use crate::service::app::{self, AppUpdate};
use crate::state::app::AppState;
use crate::web::dashboard::dto::{AppDetailView, AppFormData, AppFormView, AppListView};
use crate::web::dashboard::guard::{AdminContext, AdminPage};
use crate::web::util::{self, CsrfOnly, view_response};

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
    let access = admin.access.clone();
    let AdminPage {
        layout,
        csrf_token,
        jar,
        ..
    } = AdminPage::new(&state, jar, admin);

    let page_num = query.page.unwrap_or(1).max(1);
    let q = query.q.unwrap_or_default();
    let status_filter = query.status.unwrap_or_default();

    let (apps_list, total_pages) =
        match crate::db::helper::admin::list_apps(&state.db, page_num, &q, &status_filter, &access)
            .await
        {
            Ok(data) => data,
            Err(error) => return util::dependency_error(error),
        };

    let tpl = AppListView {
        layout,
        csrf_token,
        apps: apps_list.into_iter().map(Into::into).collect(),
        page: page_num,
        total_pages,
        q,
        status_filter,
    };
    view_response("AppListView", tpl, jar)
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

    let tpl = AppFormView {
        layout,
        csrf_token,
        mode: "create".to_owned(),
        app_id: String::new(),
        form: AppFormData::default(),
        error: String::new(),
    };
    view_response("AppFormView", tpl, jar)
}

pub async fn create(
    State(state): State<AppState>,
    jar: CookieJar,
    admin: super::guard::AdminContext,
    axum::Form(form): axum::Form<AppFormData>,
) -> Response {
    if let Some(response) = util::verify_csrf_or_json_error(&jar, &form.csrf_token, &state) {
        return response;
    }

    let input = app_input(&form);
    util::management_response(
        app::create(&state.db, &admin.actor(&state), form.code.trim(), input).await,
    )
}

pub async fn detail(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<uuid::Uuid>,
    admin: AdminContext,
) -> Response {
    let access = admin.access.clone();
    let AdminPage {
        layout,
        csrf_token,
        jar,
        ..
    } = AdminPage::new(&state, jar, admin);
    let app = match crate::db::helper::admin::find_app_by_id(&state.db, id).await {
        Ok(Some(a)) => a,
        Err(error) => return util::dependency_error(error),
        _ => return Redirect::to("/dashboard/apps").into_response(),
    };

    let clients = if !access.can_app(id, P::ClientsRead) {
        Vec::new()
    } else {
        match crate::db::helper::admin::list_clients_by_app(&state.db, id).await {
            Ok(data) => data,
            Err(error) => return util::dependency_error(error),
        }
    };

    let tpl = AppDetailView {
        layout,
        csrf_token,
        app: app.into(),
        clients: clients.into_iter().map(Into::into).collect(),
        error: String::new(),
    };
    view_response("AppDetailView", tpl, jar)
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
    let app = match crate::db::helper::admin::find_app_by_id(&state.db, id).await {
        Ok(Some(a)) => a,
        Err(error) => return util::dependency_error(error),
        _ => return Redirect::to("/dashboard/apps").into_response(),
    };
    if app.system {
        return Redirect::to(&format!("/dashboard/apps/{}", app.id)).into_response();
    }

    let tpl = AppFormView {
        layout,
        csrf_token,
        mode: "edit".to_owned(),
        app_id: app.id.to_string(),
        form: AppFormData {
            csrf_token: String::new(),
            code: app.code.clone(),
            name: app.name.clone(),
            description: app.description.unwrap_or_default(),
            homepage_url: app.homepage_url.unwrap_or_default(),
            logo_url: app.logo_url.unwrap_or_default(),
        },
        error: String::new(),
    };
    view_response("AppFormView", tpl, jar)
}

pub async fn update(
    State(state): State<AppState>,
    jar: CookieJar,
    admin: super::guard::AdminContext,
    Path(id): Path<uuid::Uuid>,
    axum::Form(form): axum::Form<AppFormData>,
) -> Response {
    if let Some(response) = util::verify_csrf_or_json_error(&jar, &form.csrf_token, &state) {
        return response;
    }
    util::management_response(
        app::update(&state.db, &admin.actor(&state), id, app_input(&form)).await,
    )
}

fn app_input(form: &AppFormData) -> AppUpdate {
    AppUpdate {
        name: form.name.trim().to_owned(),
        description: util::empty_or_opt(&form.description),
        homepage_url: util::empty_or_opt(&form.homepage_url),
        logo_url: util::empty_or_opt(&form.logo_url),
        tenant_mode: form.tenant_mode.clone(),
    }
}

pub async fn toggle_status(
    State(state): State<AppState>,
    jar: CookieJar,
    admin: super::guard::AdminContext,
    Path(id): Path<uuid::Uuid>,
    axum::Form(form): axum::Form<CsrfOnly>,
) -> Response {
    if let Some(response) = util::verify_csrf_or_json_error(&jar, &form.csrf_token, &state) {
        return response;
    }
    util::management_response(app::toggle_status(&state.db, &admin.actor(&state), id).await)
}
