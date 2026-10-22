use crate::db::entity::oauth_clients as oc;
use crate::state::app::AppState;

pub(super) struct TokenIssuer<'a> {
    state: &'a AppState,
    client: &'a oc::Model,
    signing: &'a crate::db::helper::signing_key::SigningKeyMaterial,
}

impl<'a> TokenIssuer<'a> {
    pub(super) fn new(
        state: &'a AppState,
        client: &'a oc::Model,
        signing: &'a crate::db::helper::signing_key::SigningKeyMaterial,
    ) -> Self {
        Self {
            state,
            client,
            signing,
        }
    }

    pub(super) fn issue_access_token(
        &self,
        user_id: uuid::Uuid,
        scopes: &str,
        session_id: Option<uuid::Uuid>,
    ) -> Result<String, jsonwebtoken::errors::Error> {
        let sid = session_id.map(|id| id.to_string());
        pero_utils::oauth::jwt::sign_access_token_with_key(
            &pero_utils::oauth::jwt::AccessTokenParams {
                issuer: &self.state.config.oidc.issuer,
                user_id: &user_id.to_string(),
                client_identifier: &self.client.identifier,
                scopes,
                ttl_seconds: self.client.access_token_ttl_seconds as i64,
                session_id: sid.as_deref(),
                kid: Some(&self.signing.kid),
            },
            self.state
                .signing_keys
                .get(&self.signing.private_key)?
                .as_ref(),
        )
    }

    pub(super) fn issue_id_token(
        &self,
        user: &crate::db::entity::users::Model,
        scopes: &[String],
        nonce: Option<&str>,
        session: &crate::db::entity::sso_sessions::Model,
        access_token: Option<&str>,
        code_hash_input: Option<&str>,
    ) -> Result<String, jsonwebtoken::errors::Error> {
        let sid = session.id.to_string();
        let id_user = crate::service::scope::user_claims(user, scopes);
        pero_utils::oauth::jwt::sign_id_token_with_key(
            &pero_utils::oauth::jwt::IdTokenParams {
                issuer: &self.state.config.oidc.issuer,
                user_id: &user.id.to_string(),
                client_identifier: &self.client.identifier,
                nonce,
                auth_time: Some(session.authenticated_at.unix_timestamp()),
                at_hash: access_token
                    .map(pero_utils::oauth::jwt::oidc_hash)
                    .as_deref(),
                c_hash: code_hash_input
                    .map(pero_utils::oauth::jwt::oidc_hash)
                    .as_deref(),
                user: &id_user,
                ttl_seconds: self.client.id_token_ttl_seconds as i64,
                session_id: Some(&sid),
                kid: Some(&self.signing.kid),
            },
            self.state
                .signing_keys
                .get(&self.signing.private_key)?
                .as_ref(),
        )
    }
}
