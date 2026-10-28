//! Audit metadata for authenticated dashboard writes; request/response bodies are never stored.
use axum::{
    body::Body,
    extract::{MatchedPath, Path, Query, State},
    http::Request,
    response::{IntoResponse, Response},
};
use axum_extra::extract::CookieJar;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter, QueryOrder, Set,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::guard::{AdminContext, AdminPage};
use crate::{db::entity::audit_events, state::app::AppState, web::util};

#[derive(Clone, Copy)]
pub struct AuditId(pub Uuid);

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
        details: Set(serde_json::json!({})),
        created_at: Set(time::OffsetDateTime::now_utc()),
    }
}

pub async fn run(
    state: &AppState,
    mut req: Request<Body>,
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
    let target = req.uri().path().to_owned();
    let before = match snapshot(&state.db, &target).await {
        Ok(v) => v,
        Err(e) => return util::dependency_error(e),
    };
    let event = match pending_event(&req, actor, ip).insert(&state.db).await {
        Ok(event) => event,
        Err(error) => return util::dependency_error(error),
    };
    req.extensions_mut().insert(AuditId(event.id));
    let response = next.run(req).await;
    let status = response.status();
    let after = match snapshot(&state.db, &target).await {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(%e,audit_id=%event.id,"Audit snapshot unavailable; pending retained");
            return response;
        }
    };
    let result = audit_events::ActiveModel {
        id: Set(event.id),
        outcome: Set(if status.is_success() {
            "success"
        } else {
            "failure"
        }
        .into()),
        http_status: Set(Some(status.as_u16() as i32)),
        details: Set(changes(before, after)),
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
    #[serde(default)]
    pub q: String,
    #[serde(default)]
    pub action: String,
    #[serde(default)]
    pub target: String,
    #[serde(default)]
    pub request_id: String,
    pub ip: Option<ipnetwork::IpNetwork>,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub from: Option<time::OffsetDateTime>,
    #[serde(default, with = "time::serde::rfc3339::option")]
    pub to: Option<time::OffsetDateTime>,
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
    user_agent: Option<String>,
    details: serde_json::Value,
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
    if query.from.zip(query.to).is_some_and(|(from, to)| from > to) {
        return pero_api_axum::json_error("invalid_request");
    }
    let mut select = audit_events::Entity::find();
    if !query.q.is_empty() {
        select = select.filter(audit_events::Column::ActorUsername.contains(&query.q));
    }
    if !query.action.is_empty() {
        select = select.filter(audit_events::Column::Action.eq(&query.action));
    }
    if !query.target.is_empty() {
        select = select.filter(audit_events::Column::Target.contains(&query.target));
    }
    if !query.request_id.is_empty() {
        select = select.filter(audit_events::Column::RequestId.eq(&query.request_id));
    }
    if let Some(ip) = query.ip {
        select = select.filter(audit_events::Column::Ip.eq(ip));
    }
    if let Some(from) = query.from {
        select = select.filter(audit_events::Column::CreatedAt.gte(from));
    }
    if let Some(to) = query.to {
        select = select.filter(audit_events::Column::CreatedAt.lte(to));
    }
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
                user_agent: event.user_agent,
                details: event.details,
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

/// Explicitly select safe configuration fields; never serialize persistence models.
async fn snapshot(
    db: &sea_orm::DatabaseConnection,
    target: &str,
) -> Result<serde_json::Value, sea_orm::DbErr> {
    use sea_orm::{DbBackend, FromQueryResult, Statement};
    let parts = target.split('/').collect::<Vec<_>>();
    let Some(id) = parts.get(3).and_then(|v| Uuid::parse_str(v).ok()) else {
        return Ok(serde_json::json!({}));
    };
    let sql = match parts.get(2).copied() {
        Some("apps") => {
            "SELECT jsonb_build_object('name',name,'code',code,'status',status,'homepage_url',homepage_url) AS value FROM apps WHERE id=$1"
        }
        Some("users") => {
            "SELECT jsonb_build_object('username',username,'nickname',nickname,'status',status,'email_verified',email_verified_at IS NOT NULL,'phone_verified',phone_verified_at IS NOT NULL) AS value FROM users WHERE id=$1"
        }
        Some("clients") => {
            "SELECT jsonb_build_object('identifier',identifier,'status',status,'type',type,'redirect_uris',redirect_uris,'post_logout_redirect_uris',post_logout_redirect_uris,'scopes',scopes,'grant_types',grant_types,'require_pkce',require_pkce,'access_token_ttl_seconds',access_token_ttl_seconds,'refresh_token_ttl_seconds',refresh_token_ttl_seconds,'id_token_ttl_seconds',id_token_ttl_seconds,'previous_secret_expires_at',previous_secret_expires_at) AS value FROM oauth_clients WHERE id=$1"
        }
        Some("enrollments") => {
            "SELECT jsonb_build_object('status',status,'reason',reason,'approved_by',approved_by,'approved_at',approved_at,'last_sent_at',last_sent_at) AS value FROM enrollments WHERE id=$1"
        }
        _ => return Ok(serde_json::json!({})),
    };
    #[derive(FromQueryResult)]
    struct Snapshot {
        value: serde_json::Value,
    }
    Ok(Snapshot::find_by_statement(Statement::from_sql_and_values(
        DbBackend::Postgres,
        sql,
        [id.into()],
    ))
    .one(db)
    .await?
    .map(|v| v.value)
    .unwrap_or(serde_json::json!({})))
}
fn changes(before: serde_json::Value, after: serde_json::Value) -> serde_json::Value {
    let mut result = serde_json::Map::new();
    if let Some(fields) = before.as_object() {
        for (key, value) in fields {
            if after.get(key) != Some(value) {
                result.insert(
                    key.clone(),
                    serde_json::json!({"before":value,"after":after.get(key)}),
                );
            }
        }
    }
    serde_json::Value::Object(result)
}
pub async fn detail(
    State(state): State<AppState>,
    jar: CookieJar,
    admin: AdminContext,
    Path(id): Path<Uuid>,
) -> Response {
    let event = match audit_events::Entity::find_by_id(id).one(&state.db).await {
        Ok(Some(e)) => e,
        Ok(None) => return axum::http::StatusCode::NOT_FOUND.into_response(),
        Err(e) => return util::dependency_error(e),
    };
    let p = AdminPage::new(&state, jar, admin);
    util::view_response(
        "AuditDetailView",
        serde_json::json!({"layout":p.layout,"csrf_token":p.csrf_token,"event":{"id":event.id,"actor_id":event.actor_id,"actor_username":event.actor_username,"action":event.action,"target":event.target,"ip":event.ip.map(|v|v.to_string()),"user_agent":event.user_agent,"request_id":event.request_id,"outcome":event.outcome,"http_status":event.http_status,"created_at":event.created_at.format(&time::format_description::well_known::Rfc3339).unwrap_or_default(),"details":event.details}}),
        p.jar,
    )
}
