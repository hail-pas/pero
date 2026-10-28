use super::guard::{AdminContext, AdminPage};
use crate::{
    service::{ManagementError, enrollment as svc},
    state::app::AppState,
    web::util,
};
use axum::{
    Form,
    extract::{Path, Query, State},
    response::Response,
};
use axum_extra::extract::CookieJar;
use sea_orm::{DbBackend, FromQueryResult, Statement};
use serde::Deserialize;
use uuid::Uuid;
#[derive(Default, Deserialize)]
pub struct Scope {
    app: Option<Uuid>,
}
#[derive(Deserialize)]
pub struct PolicyForm {
    csrf_token: String,
    app: Option<Uuid>,
    mode: String,
    #[serde(default)]
    domains: String,
    #[serde(default)]
    approval_required: bool,
    #[serde(default)]
    emergency_stop: bool,
    #[serde(default)]
    inherit: bool,
    version: i64,
}
pub async fn get(
    State(state): State<AppState>,
    jar: CookieJar,
    admin: AdminContext,
    Query(scope): Query<Scope>,
) -> Response {
    let page = AdminPage::new(&state, jar, admin);
    let result=async {
        let mut policy=svc::policy(&state.db,scope.app).await?;
        let inherited=scope.app.is_some() && policy.app_id.is_none();
        policy.app_id=scope.app;
        let rows=svc::Enrollment::find_by_statement(Statement::from_sql_and_values(DbBackend::Postgres,"SELECT * FROM enrollments WHERE app_id IS NOT DISTINCT FROM $1 ORDER BY created_at DESC LIMIT 100",[scope.app.into()])).all(&state.db).await?;
        Ok::<_,ManagementError>((policy,inherited,rows))
    }.await;
    match result {
        Ok((policy, inherited, rows)) => util::view_response(
            "EnrollmentAdminView",
            serde_json::json!({"layout":page.layout,"csrf_token":page.csrf_token,"policy":policy,"inherited":inherited,"rows":rows}),
            page.jar,
        ),
        Err(e) => util::management_response(Err(e)),
    }
}
pub async fn save(
    State(state): State<AppState>,
    jar: CookieJar,
    admin: AdminContext,
    Form(f): Form<PolicyForm>,
) -> Response {
    if let Some(e) = util::verify_csrf_or_json_error(&jar, &f.csrf_token, &state) {
        return e;
    }
    util::management_response(
        svc::save_policy(
            &state,
            &admin.session,
            svc::Policy {
                id: f.app.unwrap_or(Uuid::nil()),
                app_id: f.app,
                mode: f.mode,
                domains: util::parse_comma_list(&f.domains),
                approval_required: f.approval_required,
                emergency_stop: f.emergency_stop,
                version: f.version,
            },
            f.inherit,
        )
        .await,
    )
}
#[derive(Deserialize)]
pub struct Invite {
    csrf_token: String,
    email: String,
    app: Option<Uuid>,
    #[serde(default)]
    domain_exception: bool,
    #[serde(default)]
    reason: String,
}
pub async fn invite(
    State(state): State<AppState>,
    jar: CookieJar,
    admin: AdminContext,
    Form(f): Form<Invite>,
) -> Response {
    if let Some(e) = util::verify_csrf_or_json_error(&jar, &f.csrf_token, &state) {
        return e;
    }
    util::management_response(
        svc::start(
            &state,
            &f.email,
            f.app,
            Some((&admin.session, f.domain_exception, &f.reason)),
        )
        .await,
    )
}
#[derive(Deserialize)]
pub struct Decision {
    csrf_token: String,
    action: String,
    #[serde(default)]
    reason: String,
}
pub async fn manage(
    State(state): State<AppState>,
    jar: CookieJar,
    admin: AdminContext,
    Path(id): Path<Uuid>,
    Form(f): Form<Decision>,
) -> Response {
    if let Some(e) = util::verify_csrf_or_json_error(&jar, &f.csrf_token, &state) {
        return e;
    }
    util::management_response(svc::manage(&state, &admin.session, id, &f.action, &f.reason).await)
}
