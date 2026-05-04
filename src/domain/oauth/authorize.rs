use base64::Engine;

use crate::domain::app::repo::AppStore;
use crate::domain::oauth::error::OAuth2Error;
use crate::domain::oauth::models::{
    CreateClientRequest, OAuth2Client, OAuth2ClientDTO, UpdateClientRequest,
};
use crate::domain::oauth::repo::OAuth2ClientStore;
use crate::shared::page::PageData;

pub use crate::domain::oauth::token_exchange::{exchange_token, revoke_token};

use crate::domain::oauth::client_dto::ClientCredentials;
use crate::shared::constants::oauth2 as oauth2_constants;
use crate::shared::constants::security::FAKE_BCRYPT_HASH;
use crate::shared::error::AppError;

pub enum InvalidClientError {
    BadRequest,
    Unauthorized,
}

pub async fn authenticate_client(
    clients: &dyn OAuth2ClientStore,
    apps: &dyn AppStore,
    client_id: &str,
    client_secret: &str,
    grant_type: Option<&str>,
    require_enabled: bool,
    invalid_client_error: InvalidClientError,
) -> Result<OAuth2Client, AppError> {
    let client = match clients.find_by_client_id(client_id).await? {
        Some(client) => client,
        None => {
            fake_secret_probe(client_secret);
            return Err(match invalid_client_error {
                InvalidClientError::BadRequest => OAuth2Error::InvalidClient.into(),
                InvalidClientError::Unauthorized => AppError::Unauthorized,
            });
        }
    };

    if require_enabled && !client.enabled {
        return Err(match invalid_client_error {
            InvalidClientError::BadRequest => OAuth2Error::ClientDisabled.into(),
            InvalidClientError::Unauthorized => AppError::Forbidden("client is disabled".into()),
        });
    }
    if let Some(grant_type) = grant_type {
        ensure_client_grant_allowed(&client, grant_type)?;
    }
    if !client.verify_secret(client_secret)? {
        return Err(match invalid_client_error {
            InvalidClientError::BadRequest => OAuth2Error::InvalidClientCredentials.into(),
            InvalidClientError::Unauthorized => OAuth2Error::InvalidClientCredentials.into(),
        });
    }
    if require_enabled {
        ensure_app_enabled(apps, &client).await?;
    }
    Ok(client)
}

pub fn parse_basic_client_auth_header(auth_header: &str) -> Result<(String, String), AppError> {
    let encoded = auth_header
        .strip_prefix("Basic ")
        .or_else(|| auth_header.strip_prefix("basic "))
        .ok_or_else(|| OAuth2Error::InvalidAuthHeader)?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| AppError::Unauthorized)?;
    let decoded_str = String::from_utf8(decoded).map_err(|_| AppError::Unauthorized)?;
    let mut parts = decoded_str.splitn(2, ':');
    let raw_id = parts.next().unwrap_or("");
    let raw_secret = parts.next().unwrap_or("");
    if raw_id.is_empty() || raw_secret.is_empty() {
        return Err(AppError::Unauthorized);
    }
    let client_id = urlencoding::decode(raw_id)
        .map(|s| s.into_owned())
        .unwrap_or_else(|_| raw_id.to_string());
    let client_secret = urlencoding::decode(raw_secret)
        .map(|s| s.into_owned())
        .unwrap_or_else(|_| raw_secret.to_string());
    Ok((client_id, client_secret))
}

pub fn ensure_client_grant_allowed(
    client: &OAuth2Client,
    grant_type: &str,
) -> Result<(), AppError> {
    if client.allows_grant_type(grant_type) {
        return Ok(());
    }
    Err(OAuth2Error::UnauthorizedClient(grant_type.to_string()).into())
}

fn fake_secret_probe(client_secret: &str) {
    let _ = crate::shared::crypto::verify_secret(client_secret, FAKE_BCRYPT_HASH);
}

pub struct CreatedClient {
    pub client: OAuth2Client,
    pub client_secret: String,
}

pub async fn create_client(
    apps: &dyn AppStore,
    clients: &dyn OAuth2ClientStore,
    req: &CreateClientRequest,
) -> Result<CreatedClient, AppError> {
    apps.find_by_id(req.app_id)
        .await?
        .ok_or_else(|| AppError::NotFound("app".into()))?;

    let client_id = crate::shared::utils::random_hex_token();
    let client_secret = crate::shared::utils::random_hex_token();
    let client_secret_hash = crate::shared::crypto::hash_secret(&client_secret)?;
    let client = clients.create(&client_id, &client_secret_hash, req).await?;
    Ok(CreatedClient {
        client,
        client_secret,
    })
}

pub async fn list_clients(
    clients: &dyn OAuth2ClientStore,
    page: i64,
    page_size: i64,
) -> Result<PageData<OAuth2ClientDTO>, AppError> {
    let (clients_list, total) = clients.list(page, page_size).await?;
    let items = clients_list
        .into_iter()
        .map(OAuth2ClientDTO::from)
        .collect();
    Ok(PageData::new(items, total, page, page_size))
}

pub async fn get_client(
    clients: &dyn OAuth2ClientStore,
    id: uuid::Uuid,
) -> Result<OAuth2ClientDTO, AppError> {
    let client = clients
        .find_by_id(id)
        .await?
        .ok_or_else(|| AppError::from(OAuth2Error::InvalidClient))?;
    Ok(client.into())
}

pub async fn update_client(
    clients: &dyn OAuth2ClientStore,
    id: uuid::Uuid,
    req: &UpdateClientRequest,
) -> Result<OAuth2ClientDTO, AppError> {
    Ok(clients.update(id, req).await?.into())
}

pub async fn delete_client(
    clients: &dyn OAuth2ClientStore,
    id: uuid::Uuid,
) -> Result<(), AppError> {
    clients.delete(id).await
}

pub async fn validate_authorization_client(
    clients: &dyn OAuth2ClientStore,
    apps: &dyn AppStore,
    client_id: &str,
    redirect_uri: &str,
    requested_scopes: &[String],
) -> Result<OAuth2Client, AppError> {
    let client = clients
        .find_by_client_id(client_id)
        .await?
        .ok_or_else(|| AppError::from(OAuth2Error::InvalidClient))?;

    ensure_redirect_uri_allowed(&client, redirect_uri)?;
    ensure_authorization_client_ready(&client, requested_scopes)?;
    ensure_app_enabled(apps, &client).await?;

    Ok(client)
}

pub async fn load_authorization_client(
    clients: &dyn OAuth2ClientStore,
    client_id: &str,
) -> Result<OAuth2Client, AppError> {
    clients
        .find_by_client_id(client_id)
        .await?
        .ok_or_else(|| AppError::from(OAuth2Error::InvalidClient))
}

pub fn ensure_redirect_uri_allowed(
    client: &OAuth2Client,
    redirect_uri: &str,
) -> Result<(), AppError> {
    if client.redirect_uris.contains(&redirect_uri.to_string()) {
        Ok(())
    } else {
        Err(OAuth2Error::InvalidRedirectUri.into())
    }
}

pub fn ensure_authorization_client_ready(
    client: &OAuth2Client,
    requested_scopes: &[String],
) -> Result<(), AppError> {
    if !client.enabled {
        return Err(OAuth2Error::ClientDisabled.into());
    }
    ensure_client_grant_allowed(client, oauth2_constants::GRANT_TYPE_AUTH_CODE)?;

    for scope in requested_scopes {
        if !client.scopes.contains(scope) {
            return Err(OAuth2Error::InvalidScope(scope.clone()).into());
        }
    }

    Ok(())
}

pub fn resolve_client_credentials<T: ClientCredentials>(
    auth_header: Option<&str>,
    mut req: T,
) -> Result<T, AppError> {
    let body_has_id = req.has_client_id();

    match auth_header {
        Some(auth_value) => {
            if !auth_value.starts_with("Basic ") && !auth_value.starts_with("basic ") {
                return Err(OAuth2Error::InvalidAuthHeader.into());
            }
            if body_has_id {
                return Err(OAuth2Error::DuplicateCredentials.into());
            }
            let (id, secret) = parse_basic_client_auth_header(auth_value)?;
            req.set_client_credentials(id, secret);
        }
        None => {}
    }
    Ok(req)
}

async fn ensure_app_enabled(apps: &dyn AppStore, client: &OAuth2Client) -> Result<(), AppError> {
    let app = apps.find_by_id(client.app_id).await?.ok_or_else(|| {
        AppError::Internal(format!(
            "app {} not found for client {}",
            client.app_id, client.client_id
        ))
    })?;
    if !app.enabled {
        return Err(OAuth2Error::AppDisabled.into());
    }
    Ok(())
}

pub async fn ensure_app_enabled_pub(
    apps: &dyn AppStore,
    client: &OAuth2Client,
) -> Result<(), AppError> {
    ensure_app_enabled(apps, client).await
}
