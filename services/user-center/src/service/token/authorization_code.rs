use pero_api_axum::oauth::TokenSuccessBody;
use pero_error::protocol::oauth::OAuth2ErrorCode;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, QuerySelect, Set,
    TransactionTrait,
};

use super::token_issuer::TokenIssuer;
use super::{TokenEndpointResult, TokenRequest, TokenService};
use crate::db::entity::oauth_clients as oc;
use crate::db::enums::{CodeChallengeMethod, UserStatus};

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
                return TokenEndpointResult::error_desc(
                    OAuth2ErrorCode::InvalidRequest,
                    "code is required",
                );
            }
        };
        let redirect_uri = match &form.redirect_uri {
            Some(r) => r,
            None => {
                return TokenEndpointResult::error_desc(
                    OAuth2ErrorCode::InvalidRequest,
                    "redirect_uri is required",
                );
            }
        };

        let code_hash = pero_utils::crypto::sha256_hex(code);
        let now = time::OffsetDateTime::now_utc();
        let txn = match self.state.db.begin().await {
            Ok(txn) => txn,
            Err(e) => {
                tracing::error!("Auth code token transaction begin: {e}");
                return TokenEndpointResult::error(OAuth2ErrorCode::ServerError);
            }
        };

        if let Err(error) = self.revalidate_client(&txn, client).await {
            return error;
        }

        let owner = ac::Entity::find()
            .filter(ac::Column::CodeHash.eq(&code_hash))
            .filter(ac::Column::ClientId.eq(client.id))
            .select_only()
            .column(ac::Column::UserId)
            .column(ac::Column::AppId)
            .into_tuple::<(uuid::Uuid, uuid::Uuid)>()
            .one(&txn)
            .await;
        let (user_id, app_id) = match owner {
            Ok(Some(owner)) => owner,
            Ok(None) => return TokenEndpointResult::error(OAuth2ErrorCode::InvalidGrant),
            Err(_) => return TokenEndpointResult::error(OAuth2ErrorCode::ServerError),
        };
        match crate::service::access::lock_grant_access(&txn, user_id, app_id).await {
            Ok(true) => {}
            Ok(false) => return TokenEndpointResult::error(OAuth2ErrorCode::InvalidGrant),
            Err(_) => return TokenEndpointResult::error(OAuth2ErrorCode::ServerError),
        }

        let auth_code = match ac::Entity::find()
            .filter(ac::Column::CodeHash.eq(&code_hash))
            .filter(ac::Column::ConsumedAt.is_null())
            .filter(ac::Column::ExpiresAt.gt(now))
            .filter(ac::Column::ClientId.eq(client.id))
            .filter(ac::Column::RedirectUri.eq(redirect_uri))
            .lock_exclusive()
            .one(&txn)
            .await
        {
            Ok(Some(c)) => c,
            Ok(None) => {
                return TokenEndpointResult::error_desc(
                    OAuth2ErrorCode::InvalidGrant,
                    "Authorization code not found or expired",
                );
            }
            Err(e) => {
                tracing::error!("Auth code lookup: {e}");
                return TokenEndpointResult::error(OAuth2ErrorCode::ServerError);
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
                return TokenEndpointResult::error_desc(
                    OAuth2ErrorCode::InvalidGrant,
                    "PKCE verification failed",
                );
            }
        } else if auth_code.code_challenge.is_some() {
            return TokenEndpointResult::error_desc(
                OAuth2ErrorCode::InvalidGrant,
                "code_verifier is required",
            );
        } else if form.code_verifier.is_some() {
            return TokenEndpointResult::error_desc(
                OAuth2ErrorCode::InvalidGrant,
                "code_verifier not expected",
            );
        }

        if client.require_pkce && auth_code.code_challenge.is_none() {
            return TokenEndpointResult::error_desc(
                OAuth2ErrorCode::InvalidGrant,
                "PKCE is required for this client",
            );
        }

        let body = match self
            .issue_tokens_from_auth_code(&txn, client, &auth_code, code)
            .await
        {
            Ok(body) => body,
            Err(result) => return result,
        };

        if let Err(e) = txn.commit().await {
            tracing::error!("Auth code token transaction commit: {e}");
            return TokenEndpointResult::error(OAuth2ErrorCode::ServerError);
        }

        TokenEndpointResult::Success(body)
    }

    async fn issue_tokens_from_auth_code<C>(
        &self,
        db: &C,
        client: &oc::Model,
        auth_code: &crate::db::entity::authorization_codes::Model,
        raw_code: &str,
    ) -> Result<TokenSuccessBody, TokenEndpointResult>
    where
        C: ConnectionTrait,
    {
        let user = match crate::db::entity::users::Entity::find_by_id(auth_code.user_id)
            .one(db)
            .await
        {
            Ok(Some(u)) if u.deleted_at.is_none() && u.status == UserStatus::Active => u,
            Ok(_) => {
                return Err(TokenEndpointResult::error_desc(
                    OAuth2ErrorCode::InvalidGrant,
                    "User not found",
                ));
            }
            Err(error) => {
                tracing::error!(%error, "Authorization code user lookup failed");
                return Err(TokenEndpointResult::error(
                    OAuth2ErrorCode::TemporarilyUnavailable,
                ));
            }
        };

        let Some(session_id) = auth_code.session_id else {
            return Err(TokenEndpointResult::error_desc(
                OAuth2ErrorCode::InvalidGrant,
                "Session revoked",
            ));
        };
        let now = time::OffsetDateTime::now_utc();
        let active_session = match crate::db::helper::session::active_query(
            now,
            self.state.config.sso.session_idle_ttl_seconds,
        )
        .filter(crate::db::entity::sso_sessions::Column::Id.eq(session_id))
        .filter(crate::db::entity::sso_sessions::Column::UserId.eq(user.id))
        .one(db)
        .await
        {
            Ok(row) => row,
            Err(e) => {
                tracing::error!("Auth code session lookup: {e}");
                return Err(TokenEndpointResult::error(OAuth2ErrorCode::ServerError));
            }
        };
        let Some(active_session) = active_session else {
            return Err(TokenEndpointResult::error_desc(
                OAuth2ErrorCode::InvalidGrant,
                "Session revoked",
            ));
        };

        match crate::service::access::can_user_access_active_app(
            db,
            auth_code.user_id,
            auth_code.app_id,
        )
        .await
        {
            Ok(true) => {}
            Ok(false) => {
                return Err(TokenEndpointResult::error_desc(
                    OAuth2ErrorCode::InvalidGrant,
                    "Access revoked",
                ));
            }
            Err(e) => {
                tracing::error!("Auth code access check: {e}");
                return Err(TokenEndpointResult::error(OAuth2ErrorCode::ServerError));
            }
        }

        let signing = match require_active_signing_key(db).await {
            Ok(k) => k,
            Err(_) => return Err(TokenEndpointResult::error(OAuth2ErrorCode::ServerError)),
        };

        if !crate::service::scope::allowed(&auth_code.scopes, &client.scopes)
            || !client.redirect_uris.contains(&auth_code.redirect_uri)
        {
            return Err(TokenEndpointResult::error_desc(
                OAuth2ErrorCode::InvalidGrant,
                "Authorization policy changed",
            ));
        }
        let scopes_str = auth_code.scopes.join(" ");
        let issuer = TokenIssuer::new(self.state, client, &signing);
        let access_token = match issuer.issue_access_token(user.id, &scopes_str, Some(session_id)) {
            Ok(t) => t,
            Err(e) => {
                tracing::error!("AT sign: {e}");
                return Err(TokenEndpointResult::error(OAuth2ErrorCode::ServerError));
            }
        };

        let mut id_token = None;
        if crate::service::scope::contains(&auth_code.scopes, "openid") {
            id_token = match issuer.issue_id_token(
                &user,
                &auth_code.scopes,
                auth_code.nonce.as_deref(),
                &active_session,
                Some(&access_token),
                Some(raw_code),
            ) {
                Ok(t) => Some(t),
                Err(e) => {
                    tracing::error!("ID sign: {e}");
                    return Err(TokenEndpointResult::error(OAuth2ErrorCode::ServerError));
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
                client_id: Set(client.id),
                session_id: Set(Some(session_id)),
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
        )
        .await
        {
            Ok(true) => {}
            Ok(false) => {
                return Err(TokenEndpointResult::error_desc(
                    OAuth2ErrorCode::InvalidGrant,
                    "Authorization code already used",
                ));
            }
            Err(e) => {
                tracing::error!("Auth code consume: {e}");
                return Err(TokenEndpointResult::error(OAuth2ErrorCode::ServerError));
            }
        }

        if let Some(rt_model) = refresh_model
            && let Err(e) = rt_model.insert(db).await
        {
            tracing::error!("RT insert: {e}");
            return Err(TokenEndpointResult::error(OAuth2ErrorCode::ServerError));
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
