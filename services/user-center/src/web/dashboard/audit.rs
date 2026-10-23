//! Audit metadata for authenticated dashboard writes; request/response bodies are never stored.
use axum::{
    body::Body,
    extract::{MatchedPath, Query, State},
    http::Request,
    response::Response,
};
use axum_extra::extract::CookieJar;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter, QueryOrder, Set,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::guard::{AdminContext, AdminPage};
use crate::{db::entity::audit_events, state::app::AppState, web::util};

fn pending_event(
    req: &Request<Body>,
    actor: &crate::db::entity::users::Model,
    ip: Option<ipnetwork::IpNetwork>,
) -> audit_events::ActiveModel {
    let header = |name| {
        req.headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.chars().take(512).collect::<String>())
    };
    let id = Uuid::now_v7();
    audit_events::ActiveModel {
        id: Set(id),
        actor_id: Set(actor.id),
        actor_username: Set(actor.username.clone()),
        action: Set(req
            .extensions()
            .get::<MatchedPath>()
            .map(|p| p.as_str())
            .unwrap_or(req.uri().path())
            .to_owned()),
        target: Set(req.uri().path().to_owned()),
        ip: Set(ip),
        user_agent: Set(header("user-agent")),
        request_id: Set(header("x-request-id")),
        outcome: Set("pending".into()),
        http_status: Set(None),
        created_at: Set(time::OffsetDateTime::now_utc()),
    }
}

pub async fn run(
    state: &AppState,
    req: Request<Body>,
    actor: &crate::db::entity::users::Model,
    next: axum::middleware::Next,
) -> Response {
    if req.method() != axum::http::Method::POST {
        return next.run(req).await;
    }
    let ip = req
        .extensions()
        .get::<pero_api_axum::middleware::ResolvedClientIp>()
        .and_then(|ip| ip.0);
    let event = match pending_event(&req, actor, ip).insert(&state.db).await {
        Ok(event) => event,
        Err(error) => return util::dependency_error(error),
    };
    let response = next.run(req).await;
    let status = response.status();
    let result = audit_events::ActiveModel {
        id: Set(event.id),
        outcome: Set(if status.is_success() {
            "success"
        } else {
            "failure"
        }
        .into()),
        http_status: Set(Some(status.as_u16() as i32)),
        ..Default::default()
    }
    .update(&state.db)
    .await;
    if let Err(error) = result {
        // Keep both the durable pending record and any one-time secret in the response.
        tracing::error!(%error, audit_id = %event.id, "Audit outcome unavailable; pending record retained");
    }
    response
}

#[derive(Default, Deserialize)]
pub struct ListQuery {
    pub page: Option<u64>,
    #[serde(default)]
    pub outcome: String,
    pub actor_id: Option<Uuid>,
}
#[derive(Serialize)]
struct AuditRow {
    id: Uuid,
    actor_id: Uuid,
    actor_username: String,
    action: String,
    target: String,
    ip: Option<String>,
    outcome: String,
    http_status: Option<i32>,
    request_id: Option<String>,
    #[serde(with = "time::serde::rfc3339")]
    created_at: time::OffsetDateTime,
}
#[derive(Serialize)]
struct AuditListView {
    layout: super::dto::DashboardLayout,
    csrf_token: String,
    rows: Vec<AuditRow>,
    page: u64,
    total_pages: u64,
}
pub async fn list(
    State(state): State<AppState>,
    jar: CookieJar,
    admin: AdminContext,
    Query(query): Query<ListQuery>,
) -> Response {
    let AdminPage {
        layout,
        csrf_token,
        jar,
    } = AdminPage::new(&state, jar, admin);
    let page = query.page.unwrap_or(1).max(1);
    let mut select = audit_events::Entity::find();
    if !query.outcome.is_empty() {
        if !matches!(query.outcome.as_str(), "pending" | "success" | "failure") {
            return pero_api_axum::json_error("invalid_request");
        }
        select = select.filter(audit_events::Column::Outcome.eq(&query.outcome));
    }
    if let Some(actor) = query.actor_id {
        select = select.filter(audit_events::Column::ActorId.eq(actor));
    }
    let paginator = select
        .order_by_desc(audit_events::Column::CreatedAt)
        .order_by_desc(audit_events::Column::Id)
        .paginate(&state.db, crate::config::DASHBOARD_PAGE_SIZE);
    let result = async {
        let total = paginator.num_pages().await?;
        let rows = paginator
            .fetch_page(page - 1)
            .await?
            .into_iter()
            .map(|event| AuditRow {
                id: event.id,
                actor_id: event.actor_id,
                actor_username: event.actor_username,
                action: event.action,
                target: event.target,
                ip: event.ip.map(|ip| ip.to_string()),
                outcome: event.outcome,
                http_status: event.http_status,
                request_id: event.request_id,
                created_at: event.created_at,
            })
            .collect();
        Ok::<_, sea_orm::DbErr>((rows, total))
    }
    .await;
    match result {
        Ok((rows, total_pages)) => util::view_response(
            "AuditListView",
            AuditListView {
                layout,
                csrf_token,
                rows,
                page,
                total_pages,
            },
            jar,
        ),
        Err(error) => util::dependency_error(error),
    }
}
