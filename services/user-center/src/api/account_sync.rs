use crate::state::app::AppState;
use axum::{
    Form,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};

#[derive(serde::Deserialize)]
pub struct Input {
    sub: uuid::Uuid,
    #[serde(default)]
    client_id: String,
    client_secret: Option<String>,
}

pub async fn snapshot(
    State(state): State<AppState>,
    source: pero_api_axum::extractor::ClientIp,
    headers: HeaderMap,
    Form(mut input): Form<Input>,
) -> Response {
    let result = async {
        let client = super::client_auth::authenticate(
            &state,
            &headers,
            &mut input.client_id,
            &mut input.client_secret,
            &format!("account-sync:{}", source.for_rate_limit()),
        )
        .await?;
        if client.r#type != crate::db::enums::OauthClientType::Confidential
            || client.account_sync_uri.is_none()
        {
            return Err(StatusCode::FORBIDDEN.into_response());
        }
        match crate::service::account_sync::snapshot(&state.db, client.id, input.sub).await {
            Ok(Some(snapshot)) => Ok(axum::Json(snapshot).into_response()),
            Ok(None) => Err(StatusCode::NOT_FOUND.into_response()),
            Err(error) => Err(crate::web::util::dependency_error(error)),
        }
    }
    .await;
    let mut response = result.unwrap_or_else(|response| response);
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    response
        .headers_mut()
        .insert(header::PRAGMA, "no-cache".parse().unwrap());
    response
}
