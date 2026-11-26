//! Scope-bounded reconciliation for clients with Account Sync enabled.
use crate::state::app::AppState;
use axum::{
    Form,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use sea_orm::{DbBackend, EntityTrait, FromQueryResult, Statement};
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
async fn client(
    s: &AppState,
    source: &str,
    headers: &HeaderMap,
    client_id: &mut String,
    client_secret: &mut Option<String>,
) -> Result<crate::db::entity::oauth_clients::Model, Box<Response>> {
    let c = super::client_auth::authenticate(s, headers, client_id, client_secret, source)
        .await
        .map_err(IntoResponse::into_response)?;
    if c.r#type != crate::db::enums::OauthClientType::Confidential || c.account_sync_uri.is_none() {
        return Err(Box::new(StatusCode::FORBIDDEN.into_response()));
    }
    let app = crate::db::entity::apps::Entity::find_by_id(c.app_id)
        .one(&s.db)
        .await
        .map_err(crate::web::util::dependency_error)?;
    if app.is_none_or(|a| a.system) {
        return Err(Box::new(StatusCode::FORBIDDEN.into_response()));
    }
    Ok(c)
}
fn no_cache(mut response: Response) -> Response {
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    response
        .headers_mut()
        .insert(header::PRAGMA, header::HeaderValue::from_static("no-cache"));
    response
}
// Point lookups and reconciliation must observe the same historical admission
// boundary and calculate all status flags from a single database snapshot.
const MEMBERSHIP_SELECT: &str = r#"
SELECT membership.*,
       (membership_status='active' AND tenant_status='active'
        AND user_active AND app_access_active AND app_allowed) AS active
FROM (
    SELECT m.tenant_id, m.user_id AS sub, t.name AS tenant_name,
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
    FROM tenant_app_history h
    JOIN tenant_members m ON m.tenant_id=h.tenant_id AND m.user_id=h.user_id
    JOIN tenants t ON t.id=m.tenant_id
    JOIN users u ON u.id=m.user_id
    JOIN user_app_access a ON a.user_id=m.user_id AND a.app_id=h.app_id
    JOIN apps app ON app.id=a.app_id
    WHERE h.app_id=$1 AND NOT app.system
) membership
WHERE true
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
        let c = client(
            &s,
            &format!("tenant-sync:{}", source.for_rate_limit()),
            &headers,
            &mut f.client_id,
            &mut f.client_secret,
        )
        .await
        .map_err(|error| *error)?;
        let row = MemberRow::find_by_statement(Statement::from_sql_and_values(
            DbBackend::Postgres,
            format!("{MEMBERSHIP_SELECT} AND tenant_id=$2 AND sub=$3"),
            [c.app_id.into(), f.tenant_id.into(), f.sub.into()],
        ))
        .one(&s.db)
        .await
        .map_err(crate::web::util::dependency_error)?
        .ok_or_else(|| StatusCode::NOT_FOUND.into_response())?;
        Ok(axum::Json(row).into_response())
    }
    .await;
    no_cache(result.unwrap_or_else(|e| e))
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
        let c = client(
            &s,
            &format!("reconcile:{}", source.for_rate_limit()),
            &headers,
            &mut f.client_id,
            &mut f.client_secret,
        )
        .await
        .map_err(|error| *error)?;
        let mut rows = MemberRow::find_by_statement(Statement::from_sql_and_values(
            DbBackend::Postgres,
            format!(
                "{MEMBERSHIP_SELECT} AND ($2::uuid IS NULL OR (tenant_id,sub)>($2::uuid,$3::uuid)) ORDER BY tenant_id,sub LIMIT 101"
            ),
            [c.app_id.into(), f.after_tenant_id.into(), f.after_user_id.into()],
        ))
        .all(&s.db)
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
    no_cache(result.unwrap_or_else(|e| e))
}
pub async fn accounts(
    State(s): State<AppState>,
    source: pero_api_axum::extractor::ClientIp,
    headers: HeaderMap,
    Form(mut f): Form<Request>,
) -> Response {
    let result = async {
        if f.after_tenant_id.is_some() {
            return Err(StatusCode::BAD_REQUEST.into_response());
        }
        let c = client(
            &s,
            &format!("reconcile:{}", source.for_rate_limit()),
            &headers,
            &mut f.client_id,
            &mut f.client_secret,
        )
        .await
        .map_err(|error| *error)?;
        let (rows, next) = crate::service::account_sync::page(&s.db, c.id, f.after_user_id)
            .await
            .map_err(crate::web::util::dependency_error)?;
        Ok(axum::Json(serde_json::json!({"rows": rows, "next": next})).into_response())
    }
    .await;
    no_cache(result.unwrap_or_else(|e| e))
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
WHERE EXISTS (
    SELECT 1 FROM tenant_app_history h
    WHERE h.tenant_id=t.id AND h.app_id=app.id
)
"#;

pub async fn tenant(
    State(s): State<AppState>,
    source: pero_api_axum::extractor::ClientIp,
    headers: HeaderMap,
    Form(mut f): Form<TenantInput>,
) -> Response {
    let result = async {
        let c = client(
            &s,
            &format!("reconcile:{}", source.for_rate_limit()),
            &headers,
            &mut f.client_id,
            &mut f.client_secret,
        )
        .await
        .map_err(|error| *error)?;
        let row = TenantRow::find_by_statement(Statement::from_sql_and_values(
            DbBackend::Postgres,
            format!("{TENANT_SELECT} AND t.id=$2"),
            [c.app_id.into(), f.tenant_id.into()],
        ))
        .one(&s.db)
        .await
        .map_err(crate::web::util::dependency_error)?
        .ok_or_else(|| StatusCode::NOT_FOUND.into_response())?;
        Ok(axum::Json(row).into_response())
    }
    .await;
    no_cache(result.unwrap_or_else(|e| e))
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
        let c = client(
            &s,
            &format!("reconcile:{}", source.for_rate_limit()),
            &headers,
            &mut f.client_id,
            &mut f.client_secret,
        )
        .await
        .map_err(|error| *error)?;
        let mut rows = TenantRow::find_by_statement(Statement::from_sql_and_values(
            DbBackend::Postgres,
            format!(
                "{TENANT_SELECT} AND ($2::uuid IS NULL OR t.id>$2::uuid) ORDER BY t.id LIMIT 101"
            ),
            [c.app_id.into(), f.after_tenant_id.into()],
        ))
        .all(&s.db)
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
    no_cache(result.unwrap_or_else(|e| e))
}
