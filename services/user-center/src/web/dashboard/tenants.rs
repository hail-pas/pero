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
use sea_orm::{DbBackend, FromQueryResult, Statement, TransactionTrait};
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
    _admin: AdminContext,
    Path(id): Path<Uuid>,
    Form(f): Form<util::CsrfOnly>,
) -> Response {
    if let Some(e) = util::verify_csrf_or_json_error(&jar, &f.csrf_token, &s) {
        return e;
    }
    let outcome=async {
        let txn=s.db.begin().await?;
        let updated=txn.execute_raw(Statement::from_sql_and_values(DbBackend::Postgres,
            "UPDATE tenants SET status=CASE status WHEN 'active' THEN 'disabled' ELSE 'active' END,auth_version=auth_version+1,updated_at=now() WHERE id=$1 AND kind='organization'",
            [id.into()])).await?;
        if updated.rows_affected()!=1{return Err(crate::service::ManagementError::Invalid("not_found"));}
        txn.execute_raw(Statement::from_sql_and_values(DbBackend::Postgres,
            "UPDATE refresh_tokens SET revoked_at=now(),revoke_reason='tenant_status_changed' WHERE tenant_id=$1 AND revoked_at IS NULL",
            [id.into()])).await?;
        txn.execute_raw(Statement::from_sql_and_values(DbBackend::Postgres,
            "UPDATE authorization_codes SET consumed_at=now() WHERE tenant_id=$1 AND consumed_at IS NULL",
            [id.into()])).await?;
        txn.commit().await?;
        Ok::<(),crate::service::ManagementError>(())
    }.await;
    util::management_response(outcome)
}
