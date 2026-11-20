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
    pub tenant_kind: String,
    pub tenant_status: String,
    pub membership_status: String,
    pub tenant_version: i64,
    pub membership_version: i64,
    pub active: bool,
}
#[derive(Serialize)]
struct Cursor {
    tenant_id: Uuid,
    user_id: Uuid,
}
async fn client(
    s: &AppState,
    source: &pero_api_axum::extractor::ClientIp,
    headers: &HeaderMap,
    f: &mut Request,
) -> Result<crate::db::entity::oauth_clients::Model, Response> {
    let c = super::client_auth::authenticate(
        s,
        headers,
        &mut f.client_id,
        &mut f.client_secret,
        &format!("reconcile:{}", source.for_rate_limit()),
    )
    .await?;
    if c.r#type != crate::db::enums::OauthClientType::Confidential || c.account_sync_uri.is_none() {
        return Err(StatusCode::FORBIDDEN.into_response());
    }
    let app = crate::db::entity::apps::Entity::find_by_id(c.app_id)
        .one(&s.db)
        .await
        .map_err(crate::web::util::dependency_error)?;
    if !app.is_some_and(|a| !a.system && a.status == crate::db::enums::CommonStatus::Active) {
        return Err(StatusCode::FORBIDDEN.into_response());
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
pub async fn memberships(
    State(s): State<AppState>,
    source: pero_api_axum::extractor::ClientIp,
    headers: HeaderMap,
    Form(mut f): Form<Request>,
) -> Response {
    let result=async {
        if f.after_tenant_id.is_some()!=f.after_user_id.is_some(){
            return Err(StatusCode::BAD_REQUEST.into_response());
        }
        let c=client(&s,&source,&headers,&mut f).await?;
        let mut rows=MemberRow::find_by_statement(Statement::from_sql_and_values(DbBackend::Postgres,
            "SELECT m.tenant_id,m.user_id AS sub,t.kind AS tenant_kind,t.status AS tenant_status,m.status AS membership_status,t.auth_version AS tenant_version,m.auth_version AS membership_version,(m.status='active' AND t.status='active' AND u.status='active' AND u.deleted_at IS NULL AND a.status='active' AND app.status='active' AND (t.kind='personal' OR app.organization_access='open' OR EXISTS(SELECT 1 FROM tenant_app_grants g WHERE g.tenant_id=t.id AND g.app_id=app.id))) AS active FROM tenant_members m JOIN tenants t ON t.id=m.tenant_id JOIN users u ON u.id=m.user_id JOIN user_app_access a ON a.user_id=m.user_id JOIN apps app ON app.id=a.app_id WHERE a.app_id=$1 AND (app.tenant_mode='both' OR app.tenant_mode=t.kind) AND ($2::uuid IS NULL OR (m.tenant_id,m.user_id)>($2::uuid,$3::uuid)) ORDER BY m.tenant_id,m.user_id LIMIT 101",
            [c.app_id.into(),f.after_tenant_id.into(),f.after_user_id.into()]))
            .all(&s.db).await.map_err(crate::web::util::dependency_error)?;
        let more=rows.len()>100;
        rows.truncate(100);
        let next=if more{rows.last().map(|r|Cursor{tenant_id:r.tenant_id,user_id:r.sub})}else{None};
        Ok(axum::Json(serde_json::json!({"rows":rows,"next":next})).into_response())
    }.await;
    no_cache(result.unwrap_or_else(|e| e))
}
#[derive(FromQueryResult)]
struct AccountId {
    user_id: Uuid,
}
pub async fn accounts(
    State(s): State<AppState>,
    source: pero_api_axum::extractor::ClientIp,
    headers: HeaderMap,
    Form(mut f): Form<Request>,
) -> Response {
    let result=async {
        if f.after_tenant_id.is_some(){return Err(StatusCode::BAD_REQUEST.into_response());}
        let c=client(&s,&source,&headers,&mut f).await?;
        let ids=AccountId::find_by_statement(Statement::from_sql_and_values(DbBackend::Postgres,
            "SELECT user_id FROM user_app_access WHERE app_id=$1 AND ($2::uuid IS NULL OR user_id>$2::uuid) ORDER BY user_id LIMIT 101",
            [c.app_id.into(),f.after_user_id.into()])).all(&s.db).await
            .map_err(crate::web::util::dependency_error)?;
        let more=ids.len()>100;
        let ids=ids.into_iter().take(100).collect::<Vec<_>>();
        let mut rows=Vec::with_capacity(ids.len());
        for id in &ids {
            let projection=crate::service::account_sync::snapshot(&s.db,c.id,id.user_id).await
                .map_err(crate::web::util::dependency_error)?;
            if let Some(value)=projection{rows.push(value);}
        }
        let next=if more{ids.last().map(|r|r.user_id)}else{None};
        Ok(axum::Json(serde_json::json!({"rows":rows,"next":next})).into_response())
    }.await;
    no_cache(result.unwrap_or_else(|e| e))
}
