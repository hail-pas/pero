//! Application-scoped queries for account, tenant, and membership reconciliation.
use super::account_sync::authenticate;
use crate::service::{account_sync, scope};
use crate::state::app::AppState;
use axum::{
    Form,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use sea_orm::{DbBackend, FromQueryResult, Statement};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Deserialize)]
pub struct Request {
    #[serde(default)]
    client_id: String,
    client_secret: Option<String>,
    after_tenant_id: Option<Uuid>,
    after_user_id: Option<Uuid>,
}
#[derive(FromQueryResult, Serialize)]
pub struct MemberRow {
    pub tenant_id: Uuid,
    pub sub: Uuid,
    pub tenant_name: String,
    pub membership_role: String,
    pub tenant_kind: String,
    pub tenant_status: String,
    pub membership_status: String,
    pub tenant_version: i64,
    pub membership_version: i64,
    pub app_allowed: bool,
    pub app_access_active: bool,
    pub active: bool,
}
#[derive(Serialize)]
struct Cursor {
    tenant_id: Uuid,
    user_id: Uuid,
}
// Point lookups and reconciliation must observe the same historical admission
// boundary and calculate all status flags from a single database snapshot.
const MEMBERSHIP_HISTORY: &str =
    "SELECT tenant_id, user_id FROM tenant_app_history h WHERE app_id=$1";
const MEMBERSHIP_SELECT: &str = r#"
SELECT membership.*,
       (membership_status='active' AND tenant_status='active'
        AND user_active AND app_access_active AND app_allowed) AS active
FROM (
    SELECT h.tenant_id, h.user_id AS sub, t.name AS tenant_name,
           m.role AS membership_role, t.kind AS tenant_kind,
           t.status AS tenant_status, m.status AS membership_status,
           t.auth_version AS tenant_version, m.auth_version AS membership_version,
           (u.status='active' AND u.deleted_at IS NULL) AS user_active,
           (app.status='active'
            AND (app.tenant_mode='both' OR app.tenant_mode=t.kind)
            AND (t.kind='personal' OR app.organization_access='open'
                 OR EXISTS (SELECT 1 FROM tenant_app_grants g
                            WHERE g.tenant_id=t.id AND g.app_id=app.id))) AS app_allowed,
           (a.status='active'
            AND (a.admission_origin='explicit'
                 OR (a.admission_origin='organization' AND app.organization_auto_access
                     AND t.kind='organization'))) AS app_access_active
    FROM membership_history h
    JOIN tenant_members m ON m.tenant_id=h.tenant_id AND m.user_id=h.user_id
    JOIN tenants t ON t.id=h.tenant_id
    JOIN users u ON u.id=h.user_id
    JOIN user_app_access a ON a.user_id=h.user_id AND a.app_id=$1
    JOIN apps app ON app.id=$1
    WHERE NOT app.system
) membership
"#;

#[derive(Deserialize)]
pub struct MembershipInput {
    #[serde(default)]
    client_id: String,
    client_secret: Option<String>,
    sub: Uuid,
    tenant_id: Uuid,
}

pub async fn membership(
    State(s): State<AppState>,
    source: pero_api_axum::extractor::ClientIp,
    headers: HeaderMap,
    Form(mut f): Form<MembershipInput>,
) -> Response {
    let result = async {
        let (db, c) = authenticate(
            &s,
            &headers,
            &mut f.client_id,
            &mut f.client_secret,
            &format!("tenant-sync:{}", source.for_rate_limit()),
        )
        .await?;
        let row = MemberRow::find_by_statement(Statement::from_sql_and_values(
            DbBackend::Postgres,
            format!(
                "WITH membership_history AS ({MEMBERSHIP_HISTORY} AND tenant_id=$2 AND user_id=$3)
                 {MEMBERSHIP_SELECT}"
            ),
            [c.app_id.into(), f.tenant_id.into(), f.sub.into()],
        ))
        .one(&db)
        .await
        .map_err(crate::web::util::dependency_error)?
        .ok_or_else(|| StatusCode::NOT_FOUND.into_response())?;
        Ok(axum::Json(row).into_response())
    }
    .await;
    result.unwrap_or_else(|e| e)
}

pub async fn memberships(
    State(s): State<AppState>,
    source: pero_api_axum::extractor::ClientIp,
    headers: HeaderMap,
    Form(mut f): Form<Request>,
) -> Response {
    let result = async {
        if f.after_tenant_id.is_some() != f.after_user_id.is_some() {
            return Err(StatusCode::BAD_REQUEST.into_response());
        }
        let (db, c) = authenticate(
            &s,
            &headers,
            &mut f.client_id,
            &mut f.client_secret,
            &format!("reconcile:{}", source.for_rate_limit()),
        )
        .await?;
        let mut values = vec![c.app_id.into()];
        let cursor = if let (Some(tenant), Some(user)) = (f.after_tenant_id, f.after_user_id) {
            values.extend([tenant.into(), user.into()]);
            "AND (tenant_id,user_id)>($2,$3)"
        } else {
            ""
        };
        let mut rows = MemberRow::find_by_statement(Statement::from_sql_and_values(
            DbBackend::Postgres,
            // Check both relationships before applying the history page limit.
            format!(
                "WITH membership_history AS ({MEMBERSHIP_HISTORY} {cursor}
                 AND (SELECT true FROM tenant_members m JOIN user_app_access a
                      ON a.user_id=m.user_id AND a.app_id=$1
                      WHERE m.tenant_id=h.tenant_id AND m.user_id=h.user_id)
                 ORDER BY tenant_id,user_id LIMIT 101)
                 {MEMBERSHIP_SELECT} ORDER BY tenant_id,sub"
            ),
            values,
        ))
        .all(&db)
        .await
        .map_err(crate::web::util::dependency_error)?;
        let more = rows.len() > 100;
        rows.truncate(100);
        let next = if more {
            rows.last().map(|r| Cursor {
                tenant_id: r.tenant_id,
                user_id: r.sub,
            })
        } else {
            None
        };
        Ok(axum::Json(serde_json::json!({"rows":rows,"next":next})).into_response())
    }
    .await;
    result.unwrap_or_else(|e| e)
}
#[derive(Deserialize)]
pub struct AccountsRequest {
    #[serde(default)]
    client_id: String,
    client_secret: Option<String>,
    after_tenant_id: Option<Uuid>,
    after_user_id: Option<Uuid>,
    active: Option<bool>,
    search: Option<String>,
    limit: Option<u32>,
}

pub async fn accounts(
    State(s): State<AppState>,
    source: pero_api_axum::extractor::ClientIp,
    headers: HeaderMap,
    Form(mut f): Form<AccountsRequest>,
) -> Response {
    let result = async {
        let limit = f.limit.unwrap_or(account_sync::MAX_PAGE_SIZE);
        let search = f.search.as_deref().map(str::trim);
        if f.after_tenant_id.is_some()
            || !(1..=account_sync::MAX_PAGE_SIZE).contains(&limit)
            || search.is_some_and(|term| term.is_empty() || term.contains('\0'))
        {
            return Err(StatusCode::BAD_REQUEST.into_response());
        }
        let (db, c) = authenticate(
            &s,
            &headers,
            &mut f.client_id,
            &mut f.client_secret,
            &format!("reconcile:{}", source.for_rate_limit()),
        )
        .await?;
        if search.is_some() && !scope::contains(&c.scopes, "profile") {
            return Err(StatusCode::FORBIDDEN.into_response());
        }
        let (rows, next) = account_sync::page(&db, &c, f.after_user_id, f.active, search, limit)
            .await
            .map_err(crate::web::util::dependency_error)?;
        Ok(axum::Json(serde_json::json!({"rows": rows, "next": next})).into_response())
    }
    .await;
    result.unwrap_or_else(|e| e)
}

#[derive(Deserialize)]
pub struct TenantInput {
    #[serde(default)]
    client_id: String,
    client_secret: Option<String>,
    tenant_id: Uuid,
}

#[derive(FromQueryResult, Serialize)]
pub struct TenantRow {
    pub tenant_id: Uuid,
    pub tenant_kind: String,
    pub tenant_name: String,
    pub slug: Option<String>,
    pub tenant_status: String,
    pub max_members: i32,
    pub member_count: i64,
    pub app_allowed: bool,
    pub active: bool,
}

// Historical tenants remain visible to a previously admitted application.
// Changes in tenant mode and organization admission are reported as active=false.
const TENANT_SELECT: &str = r#"
SELECT
    t.id AS tenant_id,
    t.kind AS tenant_kind,
    t.name AS tenant_name,
    t.slug::text AS slug,
    t.status AS tenant_status,
    t.max_members,
    (
        SELECT count(*)::bigint
        FROM tenant_members m
        WHERE m.tenant_id=t.id AND m.status='active'
    ) AS member_count,
    (
        app.status='active'
        AND (app.tenant_mode='both' OR app.tenant_mode=t.kind)
        AND (
            t.kind='personal' OR app.organization_access='open'
            OR EXISTS (
                SELECT 1 FROM tenant_app_grants g
                WHERE g.tenant_id=t.id AND g.app_id=app.id
            )
        )
    ) AS app_allowed,
    (
        t.status='active'
        AND app.status='active'
        AND (app.tenant_mode='both' OR app.tenant_mode=t.kind)
        AND (
            t.kind='personal' OR app.organization_access='open'
            OR EXISTS (
                SELECT 1 FROM tenant_app_grants g
                WHERE g.tenant_id=t.id AND g.app_id=app.id
            )
        )
        AND (
            t.kind<>'personal'
            OR EXISTS (
                SELECT 1
                FROM tenant_members m
                JOIN users u ON u.id=m.user_id
                WHERE m.tenant_id=t.id
                  AND m.user_id=t.owner_user_id
                  AND m.status='active'
                  AND u.status='active'
                  AND u.deleted_at IS NULL
            )
        )
    ) AS active
FROM tenants t
JOIN apps app ON app.id=$1
"#;

pub async fn tenant(
    State(s): State<AppState>,
    source: pero_api_axum::extractor::ClientIp,
    headers: HeaderMap,
    Form(mut f): Form<TenantInput>,
) -> Response {
    let result = async {
        let (db, c) = authenticate(
            &s,
            &headers,
            &mut f.client_id,
            &mut f.client_secret,
            &format!("reconcile:{}", source.for_rate_limit()),
        )
        .await?;
        let row = TenantRow::find_by_statement(Statement::from_sql_and_values(
            DbBackend::Postgres,
            format!(
                "{TENANT_SELECT} WHERE t.id=$2 AND EXISTS (
                     SELECT 1 FROM tenant_app_history WHERE app_id=$1 AND tenant_id=$2
                 )"
            ),
            [c.app_id.into(), f.tenant_id.into()],
        ))
        .one(&db)
        .await
        .map_err(crate::web::util::dependency_error)?
        .ok_or_else(|| StatusCode::NOT_FOUND.into_response())?;
        Ok(axum::Json(row).into_response())
    }
    .await;
    result.unwrap_or_else(|e| e)
}

pub async fn tenants(
    State(s): State<AppState>,
    source: pero_api_axum::extractor::ClientIp,
    headers: HeaderMap,
    Form(mut f): Form<Request>,
) -> Response {
    let result = async {
        if f.after_user_id.is_some() {
            return Err(StatusCode::BAD_REQUEST.into_response());
        }
        let (db, c) = authenticate(
            &s,
            &headers,
            &mut f.client_id,
            &mut f.client_secret,
            &format!("reconcile:{}", source.for_rate_limit()),
        )
        .await?;
        let mut values = vec![c.app_id.into()];
        let cursor = if let Some(tenant) = f.after_tenant_id {
            values.push(tenant.into());
            "AND tenant_id>$2"
        } else {
            ""
        };
        let mut rows = TenantRow::find_by_statement(Statement::from_sql_and_values(
            DbBackend::Postgres,
            // Seek to the next tenant in the history primary key. DISTINCT would
            // scan every historical membership before advancing to the next tenant.
            format!(
                "WITH RECURSIVE tenant_page(tenant_id, position) AS (
                     (SELECT tenant_id, 1 FROM tenant_app_history
                      WHERE app_id=$1 {cursor} ORDER BY tenant_id LIMIT 1)
                     UNION ALL
                     SELECT next.tenant_id, p.position + 1
                     FROM tenant_page p
                     CROSS JOIN LATERAL (
                         SELECT tenant_id FROM tenant_app_history
                         WHERE app_id=$1 AND tenant_id>p.tenant_id
                         ORDER BY tenant_id LIMIT 1
                     ) next
                     WHERE p.position < 101
                 )
                 {TENANT_SELECT} JOIN tenant_page p ON p.tenant_id=t.id ORDER BY t.id"
            ),
            values,
        ))
        .all(&db)
        .await
        .map_err(crate::web::util::dependency_error)?;
        let more = rows.len() > 100;
        rows.truncate(100);
        let next = if more {
            rows.last().map(|row| row.tenant_id)
        } else {
            None
        };
        Ok(axum::Json(serde_json::json!({"rows": rows, "next": next})).into_response())
    }
    .await;
    result.unwrap_or_else(|e| e)
}
