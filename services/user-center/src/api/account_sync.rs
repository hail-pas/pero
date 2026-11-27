use crate::{service::account_sync, service::scope, state::app::AppState};
use axum::{
    Form,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use sea_orm::{DatabaseTransaction, EntityTrait, TransactionTrait};

#[derive(serde::Deserialize)]
pub struct Input {
    sub: Option<uuid::Uuid>,
    username: Option<String>,
    #[serde(default)]
    client_id: String,
    client_secret: Option<String>,
}

pub(super) async fn authenticate(
    state: &AppState,
    headers: &HeaderMap,
    client_id: &mut String,
    client_secret: &mut Option<String>,
    source: &str,
) -> Result<(DatabaseTransaction, crate::db::entity::oauth_clients::Model), Response> {
    use crate::db::{entity::apps, enums::OauthClientType};

    let client = super::client_auth::authenticate(state, headers, client_id, client_secret, source)
        .await
        .map_err(IntoResponse::into_response)?;
    if client.r#type != OauthClientType::Confidential || !client.account_sync_enabled {
        return Err(StatusCode::FORBIDDEN.into_response());
    }
    let db = state
        .db
        .begin()
        .await
        .map_err(crate::web::util::dependency_error)?;
    // Bind the projection to the client policy and credentials authenticated above.
    crate::service::token::TokenService::new(state)
        .revalidate_client(&db, &client)
        .await
        .map_err(IntoResponse::into_response)?;
    let app = apps::Entity::find_by_id(client.app_id)
        .one(&db)
        .await
        .map_err(crate::web::util::dependency_error)?;
    if app.is_none_or(|app| app.system) {
        return Err(StatusCode::FORBIDDEN.into_response());
    }
    Ok((db, client))
}

pub async fn snapshot(
    State(state): State<AppState>,
    source: pero_api_axum::extractor::ClientIp,
    headers: HeaderMap,
    Form(mut input): Form<Input>,
) -> Response {
    let result = async {
        let (db, client) = authenticate(
            &state,
            &headers,
            &mut input.client_id,
            &mut input.client_secret,
            &format!("account-sync:{}", source.for_rate_limit()),
        )
        .await?;
        let lookup = match (input.sub, input.username.as_deref().map(str::trim)) {
            (Some(sub), None) => account_sync::snapshot(&db, client.id, sub).await,
            (None, Some(username)) if !username.is_empty() && !username.contains('\0') => {
                if !scope::contains(&client.scopes, "profile") {
                    return Err(StatusCode::FORBIDDEN.into_response());
                }
                account_sync::snapshot_by_username(&db, client.id, username).await
            }
            _ => return Err(StatusCode::BAD_REQUEST.into_response()),
        };
        match lookup {
            Ok(Some(snapshot)) => Ok(axum::Json(snapshot).into_response()),
            Ok(None) => Err(StatusCode::NOT_FOUND.into_response()),
            Err(error) => Err(crate::web::util::dependency_error(error)),
        }
    }
    .await;
    result.unwrap_or_else(|response| response)
}
