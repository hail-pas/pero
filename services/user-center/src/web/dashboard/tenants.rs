//! Platform super-administrator organization listing and recovery operations.
use crate::{
    service::tenant_admin as svc,
    state::app::AppState,
    web::{
        dashboard::guard::{AdminContext, AdminPage},
        util,
    },
};
use axum::{
    Form,
    extract::{Path, Query, State},
    response::Response,
};
use axum_extra::extract::CookieJar;
use serde::Deserialize;
use uuid::Uuid;
pub async fn list(
    State(s): State<AppState>,
    jar: CookieJar,
    admin: AdminContext,
    Query(filter): Query<svc::Filter>,
) -> Response {
    let rows = match svc::list(&s.db, &filter).await {
        Ok(v) => v,
        Err(e) => return util::management_response(Err(e)),
    };
    let pending = match svc::pending_app_requests(&s.db).await {
        Ok(v) => v,
        Err(e) => return util::management_response(Err(e)),
    };
    let page = AdminPage::new(&s, jar, admin);
    util::view_response(
        "TenantAdminView",
        serde_json::json!({"layout":page.layout,"csrf_token":page.csrf_token,"tenants":rows,"pending_requests":pending}),
        page.jar,
    )
}
pub async fn detail(
    State(s): State<AppState>,
    jar: CookieJar,
    admin: AdminContext,
    Path(id): Path<Uuid>,
    Query(filter): Query<svc::MemberFilter>,
) -> Response {
    let tenant = match svc::get(&s.db, id).await {
        Ok(v) => v,
        Err(e) => return util::management_response(Err(e)),
    };
    let members = match svc::members(&s.db, id, &filter).await {
        Ok(v) => v,
        Err(e) => return util::management_response(Err(e)),
    };
    let apps = match svc::apps(&s.db, id).await {
        Ok(v) => v,
        Err(e) => return util::management_response(Err(e)),
    };
    let page = AdminPage::new(&s, jar, admin);
    util::view_response(
        "TenantAdminDetailView",
        serde_json::json!({"layout":page.layout,"csrf_token":page.csrf_token,"tenant":tenant,"members":members,"apps":apps}),
        page.jar,
    )
}
#[derive(Deserialize)]
pub struct Limit {
    csrf_token: String,
    max_members: i32,
}
pub async fn member_limit(
    State(s): State<AppState>,
    jar: CookieJar,
    admin: AdminContext,
    Path(id): Path<Uuid>,
    Form(f): Form<Limit>,
) -> Response {
    if let Some(e) = util::verify_csrf_or_json_error(&jar, &f.csrf_token, &s) {
        return e;
    }
    util::management_response(svc::set_limit(&s.db, &admin.actor(&s), id, f.max_members).await)
}
pub async fn promote_owner(
    State(s): State<AppState>,
    jar: CookieJar,
    admin: AdminContext,
    Path((id, user)): Path<(Uuid, Uuid)>,
    Form(f): Form<util::CsrfOnly>,
) -> Response {
    if let Some(e) = util::verify_csrf_or_json_error(&jar, &f.csrf_token, &s) {
        return e;
    }
    util::management_response(svc::promote_owner(&s.db, &admin.actor(&s), id, user).await)
}
#[derive(Deserialize)]
pub struct StatusChange {
    csrf_token: String,
    status: String,
}
pub async fn set_status(
    State(s): State<AppState>,
    jar: CookieJar,
    admin: AdminContext,
    Path(id): Path<Uuid>,
    Form(f): Form<StatusChange>,
) -> Response {
    if let Some(e) = util::verify_csrf_or_json_error(&jar, &f.csrf_token, &s) {
        return e;
    }
    util::management_response(
        crate::service::tenant::set_status_admin(&s.db, &admin.actor(&s), id, &f.status).await,
    )
}

#[derive(Deserialize)]
pub struct Grant {
    csrf_token: String,
    action: String,
}
pub async fn app_grant(
    State(s): State<AppState>,
    jar: CookieJar,
    admin: AdminContext,
    Path((id, app)): Path<(Uuid, Uuid)>,
    Form(f): Form<Grant>,
) -> Response {
    if let Some(e) = util::verify_csrf_or_json_error(&jar, &f.csrf_token, &s) {
        return e;
    }
    let allow = match f.action.as_str() {
        "grant" => true,
        "revoke" => false,
        _ => return pero_api_axum::json_error("invalid_request"),
    };
    util::management_response(svc::set_app_grant(&s.db, &admin.actor(&s), id, app, allow).await)
}

#[derive(Deserialize)]
pub struct Review {
    csrf_token: String,
    action: String,
}
pub async fn review_application(
    State(s): State<AppState>, jar: CookieJar, admin: AdminContext,
    Path((id,app)): Path<(Uuid,Uuid)>, Form(f): Form<Review>,
) -> Response {
    if let Some(e) = util::verify_csrf_or_json_error(&jar,&f.csrf_token,&s) { return e; }
    let approve = match f.action.as_str() { "approve"=>true, "reject"=>false, _=>return pero_api_axum::json_error("invalid_request") };
    util::management_response(svc::review_app_request(&s.db,&admin.actor(&s),id,app,approve).await)
}
