//! Confidential-client snapshot. Scope is limited to its application and admitted users.
use crate::state::app::AppState;
use axum::{
    Form,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use sea_orm::EntityTrait;
use serde::Deserialize;
use uuid::Uuid;
#[derive(Deserialize)]
pub struct Input {
    sub: Uuid,
    tenant_id: Uuid,
    #[serde(default)]
    client_id: String,
    client_secret: Option<String>,
}
pub async fn snapshot(
    State(s): State<AppState>,
    source: pero_api_axum::extractor::ClientIp,
    headers: HeaderMap,
    Form(mut f): Form<Input>,
) -> Response {
    let client = match super::client_auth::authenticate(
        &s,
        &headers,
        &mut f.client_id,
        &mut f.client_secret,
        &format!("tenant-sync:{}", source.for_rate_limit()),
    )
    .await
    {
        Ok(c) => c,
        Err(e) => return e,
    };
    if client.r#type != crate::db::enums::OauthClientType::Confidential
        || client.account_sync_uri.is_none()
    {
        return StatusCode::FORBIDDEN.into_response();
    }
    // Keep the original Account Sync boundary: system clients cannot read tenant membership.
    let app = match crate::db::entity::apps::Entity::find_by_id(client.app_id)
        .one(&s.db)
        .await
    {
        Ok(Some(app)) if !app.system => app,
        Ok(_) => return StatusCode::FORBIDDEN.into_response(),
        Err(error) => return crate::web::util::dependency_error(error),
    };
    if app.status != crate::db::enums::CommonStatus::Active {
        return StatusCode::FORBIDDEN.into_response();
    }
    let access = match crate::service::access::active_app_access(&s.db, f.sub, client.app_id).await
    {
        Ok(a) => a,
        Err(e) => return crate::web::util::dependency_error(e),
    };
    if access.is_none() {
        return StatusCode::NOT_FOUND.into_response();
    }
    let current =
        match crate::service::tenant_context::snapshot(&s.db, f.sub, client.app_id, f.tenant_id)
            .await
        {
            Ok(v) => v,
            Err(e) => return crate::web::util::dependency_error(e),
        };
    let active = current.as_ref().is_some_and(|v| {
        v.tenant_status == "active" && v.membership_status == "active" && v.app_allowed
    });
    let response = serde_json::json!({
        "sub": f.sub,
        "tenant_id": f.tenant_id,
        "tenant_kind": current.as_ref().map(|v|v.tenant_kind.as_str()),
        "tenant_status": current.as_ref().map(|v|v.tenant_status.as_str()),
        "membership_status": current.as_ref().map(|v|v.membership_status.as_str()),
        "app_allowed": current.as_ref().map(|v|v.app_allowed).unwrap_or(false),
        "tenant_version": current.as_ref().map(|v|v.tenant_version),
        "membership_version": current.as_ref().map(|v|v.membership_version),
        "active": active,
    });
    (
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::PRAGMA, "no-cache"),
        ],
        axum::Json(response),
    )
        .into_response()
}
