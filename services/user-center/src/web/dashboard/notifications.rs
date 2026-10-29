use axum::{
    Form,
    extract::{Path, Query, State},
    response::Response,
};
use axum_extra::extract::CookieJar;
use sea_orm::{DbBackend, FromQueryResult, Statement};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::guard::{AdminContext, AdminPage};
use crate::{state::app::AppState, web::util};

#[derive(Default, Deserialize)]
pub struct ListQuery {
    page: Option<u64>,
    #[serde(default)]
    status: String,
}
#[derive(Serialize, FromQueryResult)]
struct DeliveryRow {
    id: Uuid,
    kind: String,
    channel: String,
    recipient: String,
    status: String,
    attempts: i32,
    last_error: Option<String>,
    http_status: Option<i32>,
    #[serde(with = "time::serde::rfc3339")]
    created_at: time::OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    updated_at: time::OffsetDateTime,
    can_retry: bool,
}
#[derive(Serialize, FromQueryResult)]
struct Summary {
    pending: i64,
    overdue: i64,
    failing: i64,
}
#[derive(FromQueryResult)]
struct Count {
    total: i64,
}
#[derive(Serialize, FromQueryResult)]
struct LogoutRow {
    id: Uuid,
    identifier: String,
    attempts: i32,
    last_error: Option<String>,
    status: String,
    can_retry: bool,
    #[serde(with = "time::serde::rfc3339")]
    created_at: time::OffsetDateTime,
}
#[derive(Serialize, FromQueryResult)]
struct SyncRow {
    id: Uuid,
    user_id: Uuid,
    kind: String,
    identifier: String,
    attempts: i32,
    last_error: Option<String>,
    status: String,
    can_retry: bool,
    #[serde(with = "time::serde::rfc3339")]
    created_at: time::OffsetDateTime,
}
#[derive(Serialize)]
struct NotificationListView {
    layout: super::dto::DashboardLayout,
    csrf_token: String,
    rows: Vec<DeliveryRow>,
    logout_rows: Vec<LogoutRow>,
    sync_rows: Vec<SyncRow>,
    page: u64,
    total_pages: u64,
    enabled: bool,
    summary: Summary,
}

pub async fn list(
    State(state): State<AppState>,
    jar: CookieJar,
    admin: AdminContext,
    Query(query): Query<ListQuery>,
) -> Response {
    if !matches!(
        query.status.as_str(),
        "" | "queued" | "retrying" | "delivered" | "expired" | "cancelled"
    ) {
        return pero_api_axum::json_error("invalid_request");
    }
    let super_admin = admin.access.super_admin;
    let can_retry = admin
        .access
        .can_global(crate::service::permissions::Permission::NotificationsRetry);
    let AdminPage {
        layout,
        csrf_token,
        jar,
    } = AdminPage::new(&state, jar, admin);
    let page = query.page.unwrap_or(1).clamp(1, 1_000_000);
    let size = crate::config::DASHBOARD_PAGE_SIZE;
    let result = async {
        let summary = Summary::find_by_statement(Statement::from_string(DbBackend::Postgres,
            "SELECT count(*) AS pending,count(*) FILTER (WHERE next_attempt_at < now()-interval '5 minutes') AS overdue,count(*) FILTER (WHERE attempts>=3 AND leased_until IS NULL) AS failing FROM notification_outbox WHERE expires_at>now()".to_owned())).one(&state.db).await?.expect("aggregate row");
        let count = Count::find_by_statement(Statement::from_sql_and_values(DbBackend::Postgres,
            "SELECT count(*) AS total FROM notification_deliveries WHERE ($1='' OR status=$1)",[query.status.clone().into()])).one(&state.db).await?.expect("aggregate row");
        let rows = DeliveryRow::find_by_statement(Statement::from_sql_and_values(DbBackend::Postgres,
            "SELECT d.*,COALESCE(o.attempts>0 AND o.expires_at>now() AND o.next_attempt_at>now() AND (o.leased_until IS NULL OR o.leased_until<=now()),false) AS can_retry FROM notification_deliveries d LEFT JOIN notification_outbox o ON o.id=d.id WHERE ($1='' OR d.status=$1) ORDER BY d.created_at DESC,d.id DESC LIMIT $2 OFFSET $3",
            [query.status.into(),(size as i64).into(),((page-1)*size).into()])).all(&state.db).await?;
        Ok::<_,sea_orm::DbErr>((summary,count.total,rows))
    }.await;
    let logout_rows = if !super_admin {
        Vec::new()
    } else {
        match LogoutRow::find_by_statement(Statement::from_string(DbBackend::Postgres,
        "SELECT d.id,c.identifier::text,d.attempts,d.last_error,d.created_at,CASE WHEN d.delivered_at IS NOT NULL THEN 'delivered' WHEN d.expires_at<=now() THEN 'expired' WHEN d.attempts>0 THEN 'retrying' ELSE 'queued' END AS status,(d.delivered_at IS NULL AND d.expires_at>now() AND (d.leased_until IS NULL OR d.leased_until<=now())) AS can_retry FROM backchannel_logout_deliveries d JOIN oauth_clients c ON c.id=d.client_id ORDER BY d.created_at DESC LIMIT 100".to_owned())).all(&state.db).await { Ok(rows)=>rows,Err(e)=>return util::dependency_error(e) }
    };
    let sync_rows = if !super_admin {
        Vec::new()
    } else {
        match SyncRow::find_by_statement(Statement::from_string(DbBackend::Postgres,
            "SELECT d.id,d.user_id,d.kind,c.identifier::text,d.attempts,d.last_error,d.created_at,CASE WHEN d.delivered_at IS NOT NULL THEN 'delivered' WHEN d.cancelled_at IS NOT NULL OR c.account_sync_uri IS DISTINCT FROM d.endpoint THEN 'cancelled' WHEN d.expires_at<=now() THEN 'expired' WHEN d.attempts>0 THEN 'retrying' ELSE 'queued' END AS status,(d.delivered_at IS NULL AND d.cancelled_at IS NULL AND d.expires_at>now() AND c.status='active' AND c.account_sync_uri=d.endpoint AND (d.leased_until IS NULL OR d.leased_until<=now())) AS can_retry FROM account_sync_deliveries d JOIN oauth_clients c ON c.id=d.client_id ORDER BY d.created_at DESC,d.id DESC LIMIT 100".to_owned())).all(&state.db).await {
            Ok(rows) => rows, Err(error) => return util::dependency_error(error),
        }
    };
    match result {
        Ok((summary, total, mut rows)) => {
            for row in &mut rows {
                row.can_retry &= can_retry;
            }
            util::view_response(
                "NotificationListView",
                NotificationListView {
                    layout,
                    csrf_token,
                    rows,
                    logout_rows,
                    sync_rows,
                    page,
                    total_pages: (total as u64).div_ceil(size),
                    enabled: (state.config.notification.available("email")
                        || state.config.notification.available("phone")),
                    summary,
                },
                jar,
            )
        }
        Err(error) => util::dependency_error(error),
    }
}

pub async fn retry(
    admin: AdminContext,
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<Uuid>,
    Form(form): Form<util::CsrfOnly>,
) -> Response {
    if let Some(response) = util::verify_csrf_or_json_error(&jar, &form.csrf_token, &state) {
        return response;
    }
    util::management_response(crate::service::notify::retry(&state, &admin.actor(&state), id).await)
}

pub async fn retry_logout(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<Uuid>,
    Form(form): Form<util::CsrfOnly>,
) -> Response {
    use sea_orm::ConnectionTrait;
    if let Some(response) = util::verify_csrf_or_json_error(&jar, &form.csrf_token, &state) {
        return response;
    }
    match state.db.execute_raw(Statement::from_sql_and_values(DbBackend::Postgres,"UPDATE backchannel_logout_deliveries SET next_attempt_at=now() WHERE id=$1 AND delivered_at IS NULL AND expires_at>now() AND (leased_until IS NULL OR leased_until<=now())",[id.into()])).await {
        Ok(r) if r.rows_affected()>0=>pero_api_axum::json_ok(),Ok(_)=>pero_api_axum::json_error("notification_not_retryable"),Err(e)=>util::dependency_error(e)
    }
}

pub async fn retry_account_sync(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<Uuid>,
    Form(form): Form<util::CsrfOnly>,
) -> Response {
    use sea_orm::ConnectionTrait;
    if let Some(response) = util::verify_csrf_or_json_error(&jar, &form.csrf_token, &state) {
        return response;
    }
    match state.db.execute_raw(Statement::from_sql_and_values(DbBackend::Postgres,
        "UPDATE account_sync_deliveries d SET next_attempt_at=now() FROM oauth_clients c WHERE d.id=$1 AND c.id=d.client_id AND d.delivered_at IS NULL AND d.cancelled_at IS NULL AND d.expires_at>now() AND (d.leased_until IS NULL OR d.leased_until<=now()) AND c.status='active' AND c.account_sync_uri=d.endpoint",[id.into()])).await {
        Ok(result) if result.rows_affected()>0 => pero_api_axum::json_ok(),
        Ok(_) => pero_api_axum::json_error("notification_not_retryable"),
        Err(error) => util::dependency_error(error),
    }
}
