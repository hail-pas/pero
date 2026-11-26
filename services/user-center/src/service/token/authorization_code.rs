use pero_api_axum::oauth::TokenSuccessBody;
use pero_error::protocol::oauth::OAuth2ErrorCode;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, QuerySelect, Set,
    TransactionTrait,
};

use super::token_issuer::TokenIssuer;
use super::{TokenEndpointError, TokenEndpointResult, TokenRequest, TokenService};
use crate::db::entity::oauth_clients as oc;
use crate::db::enums::CodeChallengeMethod;
use crate::service::access::GrantAccess;

use crate::db::helper::signing_key::require_active_signing_key;

impl TokenService<'_> {
    pub(super) async fn handle_authorization_code(
        &self,
        form: &TokenRequest,
        client: &oc::Model,
    ) -> TokenEndpointResult {
        use crate::db::entity::authorization_codes as ac;

        let code = match &form.code {
            Some(c) => c,
            None => {
                return Err(TokenEndpointError::error_desc(
                    OAuth2ErrorCode::InvalidRequest,
                    "code is required",
                ));
            }
        };
        let redirect_uri = match &form.redirect_uri {
            Some(r) => r,
            None => {
                return Err(TokenEndpointError::error_desc(
                    OAuth2ErrorCode::InvalidRequest,
                    "redirect_uri is required",
                ));
            }
        };

        let code_hash = pero_utils::crypto::sha256_hex(code);
        let txn = match self.state.db.begin().await {
            Ok(txn) => txn,
            Err(e) => {
                tracing::error!("Auth code token transaction begin: {e}");
                return Err(TokenEndpointError::error(OAuth2ErrorCode::ServerError));
            }
        };

        self.revalidate_client(&txn, client).await?;

        let owner = ac::Entity::find()
            .filter(ac::Column::CodeHash.eq(&code_hash))
            .filter(ac::Column::ClientId.eq(client.id))
            .select_only()
            .column(ac::Column::UserId)
            .column(ac::Column::AppId)
            .column(ac::Column::SessionId)
            .column(ac::Column::TenantId)
            .into_tuple::<(
                uuid::Uuid,
                uuid::Uuid,
                Option<uuid::Uuid>,
                Option<uuid::Uuid>,
            )>()
            .one(&txn)
            .await;
        let (user_id, app_id, session_id, tenant_id) = match owner {
            Ok(Some(owner)) => owner,
            Ok(None) => return Err(TokenEndpointError::error(OAuth2ErrorCode::InvalidGrant)),
            Err(_) => return Err(TokenEndpointError::error(OAuth2ErrorCode::ServerError)),
        };
        let access = match crate::service::access::lock_grant_access(&txn, user_id, app_id).await {
            Ok(Some(access)) => access,
            Ok(None) => return Err(TokenEndpointError::error(OAuth2ErrorCode::InvalidGrant)),
            Err(_) => return Err(TokenEndpointError::error(OAuth2ErrorCode::ServerError)),
        };

        // Lock the session before the grant row: logout updates the session first,
        // then revokes refresh tokens and queues backchannel notifications.
        let Some(session_id) = session_id else {
            return Err(TokenEndpointError::error(OAuth2ErrorCode::InvalidGrant));
        };
        let active_session = match crate::db::helper::session::app_query(
            time::OffsetDateTime::now_utc(),
            self.state.config.sso.session_idle_ttl_seconds,
            client.app_id,
        )
        .filter(crate::db::entity::sso_sessions::Column::Id.eq(session_id))
        .filter(crate::db::entity::sso_sessions::Column::UserId.eq(user_id))
        .lock_shared()
        .one(&txn)
        .await
        {
            Ok(Some(session)) => session,
            Ok(None) => return Err(TokenEndpointError::error(OAuth2ErrorCode::InvalidGrant)),
            Err(_) => return Err(TokenEndpointError::error(OAuth2ErrorCode::ServerError)),
        };

        match crate::service::tenant_context::lock_context(&txn, user_id, tenant_id).await {
            Ok(true) => {}
            Ok(false) => return Err(TokenEndpointError::error(OAuth2ErrorCode::InvalidGrant)),
            Err(_) => return Err(TokenEndpointError::error(OAuth2ErrorCode::ServerError)),
        }
        if crate::service::app_session::lock_devices(&txn, user_id, app_id, None)
            .await
            .is_err()
        {
            return Err(TokenEndpointError::error(OAuth2ErrorCode::ServerError));
        }

        let auth_code = match ac::Entity::find()
            .filter(ac::Column::CodeHash.eq(&code_hash))
            .filter(ac::Column::ClientId.eq(client.id))
            .filter(ac::Column::RedirectUri.eq(redirect_uri))
            .lock_exclusive()
            .one(&txn)
            .await
        {
            Ok(Some(c)) => c,
            Ok(None) => {
                return Err(TokenEndpointError::error_desc(
                    OAuth2ErrorCode::InvalidGrant,
                    "Authorization code not found or expired",
                ));
            }
            Err(e) => {
                tracing::error!("Auth code lookup: {e}");
                return Err(TokenEndpointError::error(OAuth2ErrorCode::ServerError));
            }
        };

        if let (Some(challenge), Some(verifier)) = (&auth_code.code_challenge, &form.code_verifier)
        {
            let method = match auth_code.code_challenge_method {
                Some(ref m) => m,
                None => &CodeChallengeMethod::S256,
            };
            let method_str = match method {
                CodeChallengeMethod::S256 => "S256",
                CodeChallengeMethod::Plain => "plain",
            };
            if !pero_utils::oauth::pkce::verify_pkce(verifier, challenge, method_str) {
                return Err(TokenEndpointError::error_desc(
                    OAuth2ErrorCode::InvalidGrant,
                    "PKCE verification failed",
                ));
            }
        } else if auth_code.code_challenge.is_some() {
            return Err(TokenEndpointError::error_desc(
                OAuth2ErrorCode::InvalidGrant,
                "code_verifier is required",
            ));
        } else if form.code_verifier.is_some() {
            return Err(TokenEndpointError::error_desc(
                OAuth2ErrorCode::InvalidGrant,
                "code_verifier not expected",
            ));
        }

        if client.require_pkce && auth_code.code_challenge.is_none() {
            return Err(TokenEndpointError::error_desc(
                OAuth2ErrorCode::InvalidGrant,
                "PKCE is required for this client",
            ));
        }

        // Only a replay with the correct client, redirect URI and PKCE proof may revoke
        // the affected authorization session.
        if auth_code.consumed_at.is_some() {
            let Some(sid) = auth_code.client_session_id else {
                return Err(TokenEndpointError::error(OAuth2ErrorCode::InvalidGrant));
            };
            match crate::service::app_session::sso_for_client(
                &txn,
                sid,
                auth_code.user_id,
                client.id,
                client.app_id,
                auth_code.tenant_id,
            )
            .await
            {
                Ok(Some(id)) if id == session_id => {}
                Ok(_) => return Err(TokenEndpointError::error(OAuth2ErrorCode::InvalidGrant)),
                Err(_) => return Err(TokenEndpointError::error(OAuth2ErrorCode::ServerError)),
            }
            // A consumed code from a withdrawn tenant grant cannot revoke SSO.
            match crate::service::tenant_context::grant_context_is_current(
                &txn,
                auth_code.user_id,
                auth_code.app_id,
                auth_code.tenant_id,
                auth_code.tenant_version,
                auth_code.tenant_member_version,
            )
            .await
            {
                Ok(true) => {}
                Ok(false) => return Err(TokenEndpointError::error(OAuth2ErrorCode::InvalidGrant)),
                Err(_) => return Err(TokenEndpointError::error(OAuth2ErrorCode::ServerError)),
            }
            if let Err(error) = crate::service::app_session::revoke_client(
                &txn,
                sid,
                auth_code.user_id,
                client.id,
                "authorization_code_reuse",
            )
            .await
            {
                tracing::error!(%error, "Authorization code replay revocation failed");
                return Err(TokenEndpointError::error(
                    OAuth2ErrorCode::TemporarilyUnavailable,
                ));
            }
            if let Err(error) = txn.commit().await {
                tracing::error!(%error, "Authorization code replay commit failed");
                return Err(TokenEndpointError::error(
                    OAuth2ErrorCode::TemporarilyUnavailable,
                ));
            }
            return Err(TokenEndpointError::error_desc(
                OAuth2ErrorCode::InvalidGrant,
                "Authorization code already used",
            ));
        }

        if auth_code.expires_at <= time::OffsetDateTime::now_utc() {
            return Err(TokenEndpointError::error_desc(
                OAuth2ErrorCode::InvalidGrant,
                "Authorization code expired",
            ));
        }

        let body = self
            .issue_tokens_from_auth_code(&txn, client, &auth_code, code, &access, &active_session)
            .await?;

        if let Err(e) = txn.commit().await {
            tracing::error!("Auth code token transaction commit: {e}");
            return Err(TokenEndpointError::error(OAuth2ErrorCode::ServerError));
        }

        Ok(body)
    }

    async fn issue_tokens_from_auth_code<C>(
        &self,
        db: &C,
        client: &oc::Model,
        auth_code: &crate::db::entity::authorization_codes::Model,
        raw_code: &str,
        access: &GrantAccess,
        active_session: &crate::db::entity::sso_sessions::Model,
    ) -> TokenEndpointResult
    where
        C: ConnectionTrait,
    {
        let user = &access.user;
        let sso_session_id = active_session.id;

        let tenant = if let Some(id) = auth_code.tenant_id {
            let ctx = crate::service::tenant_context::active(db, user.id, client.app_id, id)
                .await
                .map_err(|_| TokenEndpointError::error(OAuth2ErrorCode::ServerError))?
                .ok_or(TokenEndpointError::error(OAuth2ErrorCode::InvalidGrant))?;
            if Some(ctx.tenant_version) != auth_code.tenant_version
                || Some(ctx.tenant_member_version) != auth_code.tenant_member_version
            {
                return Err(TokenEndpointError::error(OAuth2ErrorCode::InvalidGrant));
            }
            Some(ctx)
        } else {
            None
        };
        if !access.app.system && tenant.is_none() {
            return Err(TokenEndpointError::error(OAuth2ErrorCode::InvalidGrant));
        }
        if !crate::service::scope::allowed(&auth_code.scopes, &client.scopes)
            || !client.redirect_uris.contains(&auth_code.redirect_uri)
        {
            return Err(TokenEndpointError::error_desc(
                OAuth2ErrorCode::InvalidGrant,
                "Authorization policy changed",
            ));
        }
        let openid = crate::service::scope::contains(&auth_code.scopes, "openid");
        let ttl = if openid {
            client
                .access_token_ttl_seconds
                .max(client.id_token_ttl_seconds)
        } else {
            client.access_token_ttl_seconds
        };
        let signing = match require_active_signing_key(db).await {
            Ok(k) => k,
            Err(_) => return Err(TokenEndpointError::error(OAuth2ErrorCode::ServerError)),
        };
        let session_id = crate::service::app_session::admit(
            db,
            access,
            auth_code,
            sso_session_id,
            self.state.config.sso.session_idle_ttl_seconds,
        )
        .await
        .map_err(|error| {
            tracing::error!(%error, "Application session admission failed");
            TokenEndpointError::error(OAuth2ErrorCode::ServerError)
        })?
        .ok_or(TokenEndpointError::error_desc(
            OAuth2ErrorCode::InvalidGrant,
            "Application session changed; authorize again",
        ))?;
        let scopes_str = auth_code.scopes.join(" ");
        let issuer = TokenIssuer::new(self.state, client, &signing);
        let access_token = match issuer.issue_access_token(
            user.id,
            &scopes_str,
            Some(session_id),
            access.token_version,
            tenant.as_ref(),
        ) {
            Ok(t) => t,
            Err(e) => {
                tracing::error!("AT sign: {e}");
                return Err(TokenEndpointError::error(OAuth2ErrorCode::ServerError));
            }
        };

        let mut id_token = None;
        if openid {
            id_token = match issuer.issue_id_token(
                user,
                &auth_code.scopes,
                active_session,
                session_id,
                super::token_issuer::AuthorizationCodeClaims {
                    nonce: auth_code.nonce.as_deref(),
                    access_token: &access_token,
                    authorization_code: raw_code,
                },
                tenant.as_ref(),
            ) {
                Ok(t) => Some(t),
                Err(e) => {
                    tracing::error!("ID sign: {e}");
                    return Err(TokenEndpointError::error(OAuth2ErrorCode::ServerError));
                }
            };
        }

        let mut refresh_token = None;
        let mut refresh_model = None;
        if client
            .grant_types
            .iter()
            .any(|grant| grant == "refresh_token")
        {
            let rt_raw = pero_utils::crypto::generate_token();
            let rt_hash = pero_utils::crypto::sha256_hex(&rt_raw);
            let now = time::OffsetDateTime::now_utc();
            let rt_expires = now + time::Duration::seconds(client.refresh_token_ttl_seconds as i64);

            let rt_model = crate::db::entity::refresh_tokens::ActiveModel {
                id: Set(uuid::Uuid::now_v7()),
                token_hash: Set(rt_hash),
                user_id: Set(user.id),
                app_id: Set(auth_code.app_id),
                tenant_id: Set(tenant.as_ref().map(|c| c.tenant_id)),
                tenant_version: Set(tenant.as_ref().map(|c| c.tenant_version)),
                tenant_member_version: Set(tenant.as_ref().map(|c| c.tenant_member_version)),
                client_id: Set(client.id),
                session_id: Set(Some(sso_session_id)),
                client_session_id: Set(Some(session_id)),
                scopes: Set(auth_code.scopes.clone()),
                created_at: Set(now),
                expires_at: Set(rt_expires),
                revoked_at: Set(None),
                revoke_reason: Set(None),
                replaced_by_id: Set(None),
            };
            refresh_model = Some(rt_model);
            refresh_token = Some(rt_raw);
        }

        let now = time::OffsetDateTime::now_utc();
        match crate::db::helper::auth_code::consume_if_valid(
            db,
            auth_code.id,
            client.id,
            &auth_code.redirect_uri,
            now,
            session_id,
        )
        .await
        {
            Ok(true) => {}
            Ok(false) => {
                return Err(TokenEndpointError::error_desc(
                    OAuth2ErrorCode::InvalidGrant,
                    "Authorization code already used",
                ));
            }
            Err(e) => {
                tracing::error!("Auth code consume: {e}");
                return Err(TokenEndpointError::error(OAuth2ErrorCode::ServerError));
            }
        }

        if let Some(rt_model) = refresh_model
            && let Err(e) = rt_model.insert(db).await
        {
            tracing::error!("RT insert: {e}");
            return Err(TokenEndpointError::error(OAuth2ErrorCode::ServerError));
        }

        if let Err(e) = signing.record_issuance(db, i64::from(ttl)).await {
            tracing::error!("Signing key issuance: {e}");
            return Err(TokenEndpointError::error(
                OAuth2ErrorCode::TemporarilyUnavailable,
            ));
        }

        Ok(TokenSuccessBody {
            access_token,
            token_type: "Bearer".to_owned(),
            expires_in: client.access_token_ttl_seconds as i64,
            refresh_token,
            id_token,
            scope: scopes_str,
        })
    }
}
