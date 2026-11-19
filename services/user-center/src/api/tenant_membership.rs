//! Confidential-client snapshot. Scope is limited to its application and admitted users.
use axum::{Form,extract::State,http::{HeaderMap,StatusCode,header},response::{IntoResponse,Response}};
use serde::Deserialize;
use uuid::Uuid;
use crate::state::app::AppState;
#[derive(Deserialize)]pub struct Input {
    sub:Uuid,tenant_id:Uuid,#[serde(default)]client_id:String,client_secret:Option<String>,
}
pub async fn snapshot(State(s):State<AppState>,source:pero_api_axum::extractor::ClientIp,headers:HeaderMap,Form(mut f):Form<Input>)->Response{
    let client=match super::client_auth::authenticate(&s,&headers,&mut f.client_id,&mut f.client_secret,&format!("tenant-sync:{}",source.for_rate_limit())).await{
        Ok(c)=>c,Err(e)=>return e,
    };
    if client.r#type!=crate::db::enums::OauthClientType::Confidential || client.account_sync_uri.is_none() {
        return StatusCode::FORBIDDEN.into_response();
    }
    let access=match crate::service::access::active_app_access(&s.db,f.sub,client.app_id).await{
        Ok(a)=>a,Err(e)=>return crate::web::util::dependency_error(e),
    };
    if access.is_none(){return StatusCode::NOT_FOUND.into_response();}
    let current=match crate::service::tenant_context::active(&s.db,f.sub,client.app_id,f.tenant_id).await{
        Ok(v)=>v,Err(e)=>return crate::web::util::dependency_error(e),
    };
    let response=serde_json::json!({
        "sub":f.sub,"tenant_id":f.tenant_id,
        "active":current.is_some(),
        "tenant_kind":current.as_ref().map(|v|v.tenant_kind.as_str()),
        "membership_status":if current.is_some(){"active"}else{"inactive"},
        "tenant_version":current.as_ref().map(|v|v.tenant_version),
        "membership_version":current.as_ref().map(|v|v.tenant_member_version)
    });
    ([(header::CACHE_CONTROL,"no-store"),(header::PRAGMA,"no-cache")],axum::Json(response)).into_response()
}
