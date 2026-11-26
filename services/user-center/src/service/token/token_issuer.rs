use crate::db::entity::oauth_clients as oc;
use crate::state::app::AppState;

pub(super) struct TokenIssuer<'a> {
    state: &'a AppState,
    client: &'a oc::Model,
    signing: &'a crate::db::helper::signing_key::SigningKeyMaterial,
}

pub(super) struct AuthorizationCodeClaims<'a> {
    pub nonce: Option<&'a str>,
    pub access_token: &'a str,
    pub authorization_code: &'a str,
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
        access_version: i64,
        tenant: Option<&crate::service::tenant_context::TenantContext>,
    ) -> Result<String, jsonwebtoken::errors::Error> {
        let sid = session_id.map(|id| id.to_string());
        let tenant_id = tenant.map(|c| c.tenant_id.to_string());
        pero_utils::oauth::jwt::sign_access_token_with_key(
            &pero_utils::oauth::jwt::AccessTokenParams {
                issuer: &self.state.config.oidc.issuer,
                user_id: &user_id.to_string(),
                client_identifier: &self.client.identifier,
                scopes,
                client_version: self.client.token_version,
                access_version,
                tenant_id: tenant_id.as_deref(),
                tenant_kind: tenant.map(|c| c.tenant_kind.clone()),
                tenant_version: tenant.map(|c| c.tenant_version),
                tenant_member_version: tenant.map(|c| c.tenant_member_version),
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
        session: &crate::db::entity::sso_sessions::Model,
        client_session_id: uuid::Uuid,
        claims: AuthorizationCodeClaims<'_>,
        tenant: Option<&crate::service::tenant_context::TenantContext>,
    ) -> Result<String, jsonwebtoken::errors::Error> {
        let sid = client_session_id.to_string();
        let tenant_id = tenant.map(|c| c.tenant_id.to_string());
        let id_user = crate::service::scope::user_claims(user, scopes);
        let access_hash = pero_utils::oauth::jwt::oidc_hash(claims.access_token);
        let code_hash = pero_utils::oauth::jwt::oidc_hash(claims.authorization_code);
        pero_utils::oauth::jwt::sign_id_token_with_key(
            &pero_utils::oauth::jwt::IdTokenParams {
                issuer: &self.state.config.oidc.issuer,
                user_id: &user.id.to_string(),
                client_identifier: &self.client.identifier,
                nonce: claims.nonce,
                tenant_id: tenant_id.as_deref(),
                auth_time: Some(session.authenticated_at.unix_timestamp()),
                at_hash: Some(&access_hash),
                c_hash: Some(&code_hash),
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
