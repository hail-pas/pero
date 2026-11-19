//! Super administrator organization status operations; tenant business data is never managed here.
use crate::{
    state::app::AppState,
    web::{
        dashboard::guard::{AdminContext, AdminPage},
        util,
    },
};
use axum::{
    Form,
    extract::{Path, State},
    response::Response,
};
use axum_extra::extract::CookieJar;
use sea_orm::{DbBackend, FromQueryResult, Statement};
use serde::Serialize;
use uuid::Uuid;
#[derive(Serialize, FromQueryResult)]
struct Row {
    id: Uuid,
    name: String,
    slug: Option<String>,
    status: String,
    members: i64,
}
pub async fn list(State(s): State<AppState>, jar: CookieJar, admin: AdminContext) -> Response {
    let page = AdminPage::new(&s, jar, admin);
    let rows=Row::find_by_statement(Statement::from_string(DbBackend::Postgres,
        "SELECT t.id,t.name,t.slug::text,t.status,(SELECT count(*)::bigint FROM tenant_members m WHERE m.tenant_id=t.id AND m.status='active') AS members FROM tenants t WHERE t.kind='organization' ORDER BY t.created_at DESC LIMIT 500".to_owned(),
    )).all(&s.db).await;
    match rows {
        Ok(rows) => util::view_response(
            "TenantAdminView",
            serde_json::json!({
                "layout":page.layout,"csrf_token":page.csrf_token,"tenants":rows
            }),
            page.jar,
        ),
        Err(e) => util::dependency_error(e),
    }
}
pub async fn toggle(
    State(s): State<AppState>,
    jar: CookieJar,
    admin: AdminContext,
    Path(id): Path<Uuid>,
    Form(f): Form<util::CsrfOnly>,
) -> Response {
    if let Some(e) = util::verify_csrf_or_json_error(&jar, &f.csrf_token, &s) {
        return e;
    }
    util::management_response(
        crate::service::tenant::toggle_status(&s.db, admin.user.id, id, true).await,
    )
}
