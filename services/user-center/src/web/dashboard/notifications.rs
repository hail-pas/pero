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
#[derive(Serialize)]
struct NotificationListView {
    layout: super::dto::DashboardLayout,
    csrf_token: String,
    rows: Vec<DeliveryRow>,
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
    match result {
        Ok((summary, total, rows)) => util::view_response(
            "NotificationListView",
            NotificationListView {
                layout,
                csrf_token,
                rows,
                page,
                total_pages: (total as u64).div_ceil(size),
                enabled: !state.config.notification.endpoint.is_empty(),
                summary,
            },
            jar,
        ),
        Err(error) => util::dependency_error(error),
    }
}

pub async fn retry(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(id): Path<Uuid>,
    Form(form): Form<util::CsrfOnly>,
) -> Response {
    if let Some(response) = util::verify_csrf_or_json_error(&jar, &form.csrf_token, &state) {
        return response;
    }
    util::management_response(crate::service::notify::retry(&state, id).await)
}
