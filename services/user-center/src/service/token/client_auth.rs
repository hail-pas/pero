use pero_error::protocol::oauth::OAuth2ErrorCode;
use sea_orm::{ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, QuerySelect};

use super::{TokenEndpointResult, TokenRequest, TokenService};
use crate::db::entity::oauth_clients as oc;
use crate::db::enums::{CommonStatus, OauthClientType};

impl TokenService<'_> {
    pub(super) async fn revalidate_client<C: ConnectionTrait>(
        &self,
        db: &C,
        authenticated: &oc::Model,
    ) -> Result<(), TokenEndpointResult> {
        let current = oc::Entity::find_by_id(authenticated.id)
            .lock_shared()
            .one(db)
            .await
            .map_err(|_| TokenEndpointResult::error(OAuth2ErrorCode::ServerError))?;
        if current.as_ref() != Some(authenticated) {
            return Err(TokenEndpointResult::unauthorized(
                "Client policy changed; authenticate again",
            ));
        }
        Ok(())
    }

    pub(super) async fn authenticate_client(
        &self,
        form: &TokenRequest,
    ) -> Result<oc::Model, TokenEndpointResult> {
        let client_identifier = form.client_id.trim();
        let client = oc::Entity::find()
            .filter(oc::Column::Identifier.eq(client_identifier))
            .one(&self.state.db)
            .await
            .map_err(|e| {
                tracing::error!("Client query: {e}");
                TokenEndpointResult::error(OAuth2ErrorCode::TemporarilyUnavailable)
            })?
            .ok_or_else(|| TokenEndpointResult::unauthorized("Client not found"))?;

        if client.status != CommonStatus::Active {
            return Err(TokenEndpointResult::unauthorized("Client is disabled"));
        }

        match client.r#type {
            OauthClientType::Confidential => {
                let secret = form.client_secret.as_deref().unwrap_or("");
                let hash = client.secret_hash.clone().unwrap_or_default();
                if hash.is_empty()
                    || !pero_utils::crypto::verify_secret_async(secret, &hash)
                        .await
                        .map_err(|_| {
                            TokenEndpointResult::error(OAuth2ErrorCode::TemporarilyUnavailable)
                        })?
                {
                    return Err(TokenEndpointResult::unauthorized("Invalid client secret"));
                }
            }
            OauthClientType::Public => {
                if form.client_secret.is_some() {
                    return Err(TokenEndpointResult::unauthorized(
                        "Public client must not send secret",
                    ));
                }
            }
        }

        if !client.grant_types.contains(&form.grant_type) {
            return Err(TokenEndpointResult::error(
                OAuth2ErrorCode::UnsupportedGrantType,
            ));
        }

        Ok(client)
    }
}
