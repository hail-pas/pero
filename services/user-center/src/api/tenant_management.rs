//! Delegated tenant operations. The validated access token supplies the actor and workspace.
use crate::{service::tenant as svc, state::app::AppState, web::util};
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use uuid::Uuid;

async fn actor(
    s: &AppState,
    h: &HeaderMap,
    tenant: Option<Uuid>,
    allow_disabled_recovery: bool,
) -> Result<Uuid, Response> {
    let token = h
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split_once(' '))
        .and_then(|(scheme, value)| scheme.eq_ignore_ascii_case("Bearer").then_some(value))
        .filter(|v| !v.is_empty())
        .ok_or_else(|| StatusCode::UNAUTHORIZED.into_response())?;
    let (claims, user, _client) = match crate::service::token_status::active_access(s, token).await
    {
        Ok(Some(v)) => v,
        Ok(None) => return Err(StatusCode::UNAUTHORIZED.into_response()),
        Err(e) => return Err(util::dependency_error(e)),
    };
    if !claims
        .scope
        .split_whitespace()
        .any(|scope| scope == "tenant.manage")
    {
        return Err(StatusCode::FORBIDDEN.into_response());
    }
    if let Some(id) = tenant
        && claims
            .tenant_id
            .as_deref()
            .and_then(|v| Uuid::parse_str(v).ok())
            != Some(id)
    {
        // A disabled organization cannot issue new tenant-bound tokens.
        // Only its owner may recover it using a valid personal-workspace token.
        if !allow_disabled_recovery || claims.tenant_kind.as_deref() != Some("personal") {
            return Err(StatusCode::FORBIDDEN.into_response());
        }
        match svc::get(&s.db, user.id, id).await {
            Ok(space) if space.status == "disabled" && space.role == "owner" => {}
            Ok(_) | Err(crate::service::ManagementError::Invalid(_)) => {
                return Err(StatusCode::FORBIDDEN.into_response());
            }
            Err(error) => return Err(util::management_response(Err(error))),
        }
    }
    Ok(user.id)
}
pub async fn list(State(s): State<AppState>, h: HeaderMap) -> Response {
    let user = match actor(&s, &h, None, false).await {
        Ok(v) => v,
        Err(e) => return e,
    };
    match svc::list(&s.db, user).await {
        Ok(rows) => Json(serde_json::json!({"rows":rows})).into_response(),
        Err(e) => util::management_response(Err(e)),
    }
}
#[derive(Deserialize)]
pub struct Create {
    name: String,
    slug: String,
}
pub async fn create(State(s): State<AppState>, h: HeaderMap, Json(f): Json<Create>) -> Response {
    let user = match actor(&s, &h, None, false).await {
        Ok(v) => v,
        Err(e) => return e,
    };
    match svc::create(&s.db, user, &f.name, &f.slug).await {
        Ok(id) => (StatusCode::CREATED, Json(serde_json::json!({"id":id}))).into_response(),
        Err(error) => util::management_response(Err(error)),
    }
}
pub async fn detail(State(s): State<AppState>, h: HeaderMap, Path(id): Path<Uuid>) -> Response {
    let user = match actor(&s, &h, Some(id), false).await {
        Ok(v) => v,
        Err(e) => return e,
    };
    match svc::get(&s.db, user, id).await {
        Ok(row) => Json(row).into_response(),
        Err(e) => util::management_response(Err(e)),
    }
}
pub async fn members(State(s): State<AppState>, h: HeaderMap, Path(id): Path<Uuid>) -> Response {
    let user = match actor(&s, &h, Some(id), false).await {
        Ok(v) => v,
        Err(e) => return e,
    };
    match svc::members(&s.db, user, id).await {
        Ok(rows) => Json(serde_json::json!({"rows":rows})).into_response(),
        Err(e) => util::management_response(Err(e)),
    }
}
#[derive(Deserialize)]
pub struct MemberChange {
    action: String,
}
pub async fn update_member(
    State(s): State<AppState>,
    h: HeaderMap,
    Path((id, target)): Path<(Uuid, Uuid)>,
    Json(f): Json<MemberChange>,
) -> Response {
    let user = match actor(&s, &h, Some(id), false).await {
        Ok(v) => v,
        Err(e) => return e,
    };
    util::management_response(svc::update_member(&s.db, user, id, target, &f.action).await)
}
#[derive(Deserialize)]
pub struct Invite {
    email: String,
    role: String,
}
pub async fn invite(
    State(s): State<AppState>,
    h: HeaderMap,
    Path(id): Path<Uuid>,
    Json(f): Json<Invite>,
) -> Response {
    let user = match actor(&s, &h, Some(id), false).await {
        Ok(v) => v,
        Err(e) => return e,
    };
    util::management_response(svc::invite(&s, user, id, &f.email, &f.role).await)
}
#[derive(Deserialize)]
pub struct Rename {
    name: String,
}
pub async fn rename(
    State(s): State<AppState>,
    h: HeaderMap,
    Path(id): Path<Uuid>,
    Json(f): Json<Rename>,
) -> Response {
    let user = match actor(&s, &h, Some(id), false).await {
        Ok(v) => v,
        Err(e) => return e,
    };
    util::management_response(svc::rename(&s.db, user, id, &f.name).await)
}
pub async fn leave(State(s): State<AppState>, h: HeaderMap, Path(id): Path<Uuid>) -> Response {
    let user = match actor(&s, &h, Some(id), false).await {
        Ok(v) => v,
        Err(e) => return e,
    };
    util::management_response(svc::leave(&s.db, user, id).await)
}
pub async fn toggle(State(s): State<AppState>, h: HeaderMap, Path(id): Path<Uuid>) -> Response {
    let user = match actor(&s, &h, Some(id), true).await {
        Ok(v) => v,
        Err(e) => return e,
    };
    util::management_response(svc::toggle_status(&s.db, user, id).await)
}
#[derive(Deserialize)]
pub struct Delete {
    confirmation: String,
}
pub async fn delete(
    State(s): State<AppState>,
    h: HeaderMap,
    Path(id): Path<Uuid>,
    Json(f): Json<Delete>,
) -> Response {
    let user = match actor(&s, &h, Some(id), false).await {
        Ok(v) => v,
        Err(e) => return e,
    };
    util::management_response(svc::delete(&s.db, user, id, &f.confirmation).await)
}
