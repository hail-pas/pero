use base64::Engine;

use crate::api::response::PageData;
use crate::domain::oauth2::error_ext;
use crate::domain::oauth2::models::{
    CreateClientRequest, OAuth2Client, OAuth2ClientDTO, UpdateClientRequest,
};
use crate::domain::oauth2::store::OAuth2ClientRepo;
use crate::shared::state::AppState;

pub use crate::domain::oauth2::token_exchange::{exchange_token, revoke_token};

use crate::domain::oauth2::dto::ClientCredentials;
use crate::shared::constants::oauth2 as oauth2_constants;
use crate::shared::constants::security::FAKE_BCRYPT_HASH;
use crate::shared::error::AppError;

pub enum InvalidClientError {
    BadRequest,
    Unauthorized,
}

pub async fn authenticate_client(
    state: &AppState,
    client_id: &str,
    client_secret: &str,
    grant_type: Option<&str>,
    require_enabled: bool,
    invalid_client_error: InvalidClientError,
) -> Result<OAuth2Client, AppError> {
    let client = match OAuth2ClientRepo::find_by_client_id(&state.db, client_id).await? {
        Some(client) => client,
        None => {
            fake_secret_probe(client_secret);
            return Err(match invalid_client_error {
                InvalidClientError::BadRequest => error_ext::invalid_client_id(),
                InvalidClientError::Unauthorized => AppError::Unauthorized,
            });
        }
    };

    if require_enabled && !client.enabled {
        return Err(match invalid_client_error {
            InvalidClientError::BadRequest => error_ext::client_disabled(),
            InvalidClientError::Unauthorized => AppError::Forbidden("client is disabled".into()),
        });
    }
    if let Some(grant_type) = grant_type {
        ensure_client_grant_allowed(&client, grant_type)?;
    }
    if !client.verify_secret(client_secret)? {
        return Err(AppError::Unauthorized);
    }
    Ok(client)
}

pub fn parse_basic_client_auth_header(auth_header: &str) -> Result<(String, String), AppError> {
    let encoded = auth_header
        .strip_prefix("Basic ")
        .or_else(|| auth_header.strip_prefix("basic "))
        .ok_or_else(|| AppError::BadRequest("Expected Basic auth".into()))?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| AppError::Unauthorized)?;
    let decoded_str = String::from_utf8(decoded).map_err(|_| AppError::Unauthorized)?;
    let mut parts = decoded_str.splitn(2, ':');
    let client_id = parts.next().unwrap_or("");
    let client_secret = parts.next().unwrap_or("");
    if client_id.is_empty() || client_secret.is_empty() {
        return Err(AppError::Unauthorized);
    }
    Ok((client_id.to_string(), client_secret.to_string()))
}

pub fn ensure_client_grant_allowed(
    client: &OAuth2Client,
    grant_type: &str,
) -> Result<(), AppError> {
    if client.allows_grant_type(grant_type) {
        return Ok(());
    }
    Err(error_ext::grant_type_not_allowed(grant_type))
}

fn fake_secret_probe(client_secret: &str) {
    let _ = bcrypt::verify(client_secret, FAKE_BCRYPT_HASH);
}

pub struct CreatedClient {
    pub client: OAuth2Client,
    pub client_secret: String,
}

pub async fn create_client(
    state: &AppState,
    req: &CreateClientRequest,
) -> Result<CreatedClient, AppError> {
    crate::domain::app::store::AppRepo::find_by_id_or_err(&state.db, req.app_id).await?;

    let client_id = crate::shared::utils::random_hex_token();
    let client_secret = crate::shared::utils::random_hex_token();
    let client_secret_hash = crate::domain::identity::service::hash_password(&client_secret)?;
    let client = OAuth2ClientRepo::create(&state.db, &client_id, &client_secret_hash, req).await?;
    Ok(CreatedClient {
        client,
        client_secret,
    })
}

pub async fn list_clients(
    state: &AppState,
    page: i64,
    page_size: i64,
) -> Result<PageData<OAuth2ClientDTO>, AppError> {
    let (clients, total) = OAuth2ClientRepo::list(&state.db, page, page_size).await?;
    let items = clients.into_iter().map(OAuth2ClientDTO::from).collect();
    Ok(PageData::new(items, total, page, page_size))
}

pub async fn get_client(state: &AppState, id: uuid::Uuid) -> Result<OAuth2ClientDTO, AppError> {
    Ok(OAuth2ClientRepo::find_by_id_or_err(&state.db, id)
        .await?
        .into())
}

pub async fn update_client(
    state: &AppState,
    id: uuid::Uuid,
    req: &UpdateClientRequest,
) -> Result<OAuth2ClientDTO, AppError> {
    Ok(OAuth2ClientRepo::update(&state.db, id, req).await?.into())
}

pub async fn delete_client(state: &AppState, id: uuid::Uuid) -> Result<(), AppError> {
    OAuth2ClientRepo::delete(&state.db, id).await
}

pub async fn validate_authorization_client(
    state: &AppState,
    client_id: &str,
    redirect_uri: &str,
    requested_scopes: &[String],
) -> Result<OAuth2Client, AppError> {
    let client = OAuth2ClientRepo::find_by_client_id(&state.db, client_id)
        .await?
        .ok_or(error_ext::invalid_client_id())?;

    ensure_redirect_uri_allowed(&client, redirect_uri)?;
    ensure_authorization_client_ready(&client, requested_scopes)?;

    Ok(client)
}

pub async fn load_authorization_client(
    state: &AppState,
    client_id: &str,
) -> Result<OAuth2Client, AppError> {
    OAuth2ClientRepo::find_by_client_id(&state.db, client_id)
        .await?
        .ok_or(error_ext::invalid_client_id())
}

pub fn ensure_redirect_uri_allowed(
    client: &OAuth2Client,
    redirect_uri: &str,
) -> Result<(), AppError> {
    if client.redirect_uris.contains(&redirect_uri.to_string()) {
        Ok(())
    } else {
        Err(error_ext::invalid_redirect_uri())
    }
}

pub fn ensure_authorization_client_ready(
    client: &OAuth2Client,
    requested_scopes: &[String],
) -> Result<(), AppError> {
    if !client.enabled {
        return Err(error_ext::client_disabled());
    }
    ensure_client_grant_allowed(client, oauth2_constants::GRANT_TYPE_AUTH_CODE)?;

    for scope in requested_scopes {
        if !client.scopes.contains(scope) {
            return Err(error_ext::scope_not_allowed(scope));
        }
    }

    Ok(())
}

pub fn resolve_client_credentials<T: ClientCredentials>(
    headers: &axum::http::HeaderMap,
    mut req: T,
) -> T {
    if let Some(auth) = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        if let Ok((id, secret)) = parse_basic_client_auth_header(auth) {
            req.set_client_credentials(id, secret);
        }
    }
    req
}
