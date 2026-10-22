use pero_api_axum::oauth::TokenSuccessBody;
use pero_error::protocol::oauth::OAuth2ErrorCode;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, QuerySelect, Set, TransactionTrait,
};

use super::token_issuer::TokenIssuer;
use super::{TokenEndpointResult, TokenRequest, TokenService};
use crate::db::entity::oauth_clients as oc;
use crate::db::enums::UserStatus;

use crate::db::helper::signing_key::require_active_signing_key;

impl TokenService<'_> {
    pub(super) async fn handle_refresh_token(
        &self,
        form: &TokenRequest,
        client: &oc::Model,
    ) -> TokenEndpointResult {
        use crate::db::entity::refresh_tokens as rt;

        let rt_raw = match &form.refresh_token {
            Some(t) => t.clone(),
            None => {
                return TokenEndpointResult::error_desc(
                    OAuth2ErrorCode::InvalidRequest,
                    "refresh_token is required",
                );
            }
        };

        let rt_hash = pero_utils::crypto::sha256_hex(&rt_raw);

        let signing = match require_active_signing_key(&self.state.db).await {
            Ok(k) => k,
            Err(_) => return TokenEndpointResult::error(OAuth2ErrorCode::ServerError),
        };

        let now = time::OffsetDateTime::now_utc();
        let rt_raw_new = pero_utils::crypto::generate_token();
        let rt_hash_new = pero_utils::crypto::sha256_hex(&rt_raw_new);
        let rt_expires = now + time::Duration::seconds(client.refresh_token_ttl_seconds as i64);
        let new_rt_id = uuid::Uuid::now_v7();

        let txn = match self.state.db.begin().await {
            Ok(txn) => txn,
            Err(e) => {
                tracing::error!("RT rotation transaction begin: {e}");
                return TokenEndpointResult::error(OAuth2ErrorCode::ServerError);
            }
        };

        if let Err(error) = self.revalidate_client(&txn, client).await {
            return error;
        }

        let owner = rt::Entity::find()
            .filter(rt::Column::TokenHash.eq(&rt_hash))
            .filter(rt::Column::ClientId.eq(client.id))
            .select_only()
            .column(rt::Column::UserId)
            .column(rt::Column::AppId)
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

        let existing = match rt::Entity::find()
            .filter(rt::Column::TokenHash.eq(&rt_hash))
            .lock_exclusive()
            .one(&txn)
            .await
        {
            Ok(Some(r)) => r,
            Ok(None) => {
                return TokenEndpointResult::error_desc(
                    OAuth2ErrorCode::InvalidGrant,
                    "Refresh token not found",
                );
            }
            Err(e) => {
                tracing::error!("RT lookup: {e}");
                return TokenEndpointResult::error(OAuth2ErrorCode::ServerError);
            }
        };

        if existing.client_id != client.id {
            return TokenEndpointResult::error_desc(
                OAuth2ErrorCode::InvalidGrant,
                "Client mismatch",
            );
        }
        if existing.revoked_at.is_some() {
            if let Some(session_id) = existing.session_id {
                if let Err(e) = txn.rollback().await {
                    tracing::warn!("RT reuse transaction rollback: {e}");
                }
                let session_svc = self.state.session_service();
                if let Err(e) = session_svc
                    .revoke_login_state(session_id, "refresh_token_reuse")
                    .await
                {
                    tracing::error!("RT reuse session revoke: {e}");
                }
            } else if let Err(e) = txn.rollback().await {
                tracing::warn!("RT reuse transaction rollback: {e}");
            }
            return TokenEndpointResult::error_desc(
                OAuth2ErrorCode::InvalidGrant,
                "Refresh token revoked",
            );
        }
        if existing.expires_at <= now {
            return TokenEndpointResult::error_desc(
                OAuth2ErrorCode::InvalidGrant,
                "Refresh token expired",
            );
        }
        if !crate::service::scope::allowed(&existing.scopes, &client.scopes) {
            let mut rev: rt::ActiveModel = existing.clone().into();
            rev.revoked_at = Set(Some(now));
            rev.revoke_reason = Set(Some("scope_revoked".to_owned()));
            if let Err(e) = rev.update(&txn).await {
                tracing::error!("RT revoke after scope change: {e}");
                return TokenEndpointResult::error(OAuth2ErrorCode::ServerError);
            }
            if let Err(e) = txn.commit().await {
                tracing::error!("RT scope revoke transaction commit: {e}");
                return TokenEndpointResult::error(OAuth2ErrorCode::ServerError);
            }
            return TokenEndpointResult::error_desc(
                OAuth2ErrorCode::InvalidGrant,
                "Refresh token scope is no longer allowed",
            );
        }

        let Some(session_id) = existing.session_id else {
            return TokenEndpointResult::error_desc(
                OAuth2ErrorCode::InvalidGrant,
                "Session revoked",
            );
        };
        let active_session = crate::db::helper::session::active_query(
            now,
            self.state.config.sso.session_idle_ttl_seconds,
        )
        .filter(crate::db::entity::sso_sessions::Column::Id.eq(session_id))
        .filter(crate::db::entity::sso_sessions::Column::UserId.eq(existing.user_id))
        .one(&txn)
        .await;
        match active_session {
            Ok(Some(_)) => {}
            Ok(None) => {
                return TokenEndpointResult::error_desc(
                    OAuth2ErrorCode::InvalidGrant,
                    "Session revoked",
                );
            }
            Err(e) => {
                tracing::error!("RT session lookup: {e}");
                return TokenEndpointResult::error(OAuth2ErrorCode::ServerError);
            }
        }

        match crate::service::access::can_user_access_active_app(
            &txn,
            existing.user_id,
            existing.app_id,
        )
        .await
        {
            Ok(true) => {}
            Ok(false) => {
                return TokenEndpointResult::error_desc(
                    OAuth2ErrorCode::InvalidGrant,
                    "Access revoked",
                );
            }
            Err(e) => {
                tracing::error!("RT access check: {e}");
                return TokenEndpointResult::error(OAuth2ErrorCode::ServerError);
            }
        }

        let user = match crate::db::entity::users::Entity::find_by_id(existing.user_id)
            .one(&txn)
            .await
        {
            Ok(Some(u)) if u.deleted_at.is_none() && u.status == UserStatus::Active => u,
            Ok(_) => {
                return TokenEndpointResult::error_desc(
                    OAuth2ErrorCode::InvalidGrant,
                    "User not found",
                );
            }
            Err(e) => {
                tracing::error!("RT user lookup: {e}");
                return TokenEndpointResult::error(OAuth2ErrorCode::ServerError);
            }
        };

        let requested =
            match crate::service::scope::refresh_scopes(form.scope.as_deref(), &existing.scopes) {
                Some(scopes) => scopes,
                None => return TokenEndpointResult::error(OAuth2ErrorCode::InvalidScope),
            };
        let scopes_str = requested.join(" ");
        let session_id = existing.session_id;
        let issuer = TokenIssuer::new(self.state, client, &signing);
        let access_token = match issuer.issue_access_token(user.id, &scopes_str, session_id) {
            Ok(t) => t,
            Err(e) => {
                tracing::error!("AT sign: {e}");
                return TokenEndpointResult::error(OAuth2ErrorCode::ServerError);
            }
        };

        let new_rt = rt::ActiveModel {
            id: Set(new_rt_id),
            token_hash: Set(rt_hash_new),
            user_id: Set(existing.user_id),
            app_id: Set(existing.app_id),
            client_id: Set(client.id),
            session_id: Set(session_id),
            scopes: Set(existing.scopes.clone()),
            created_at: Set(now),
            expires_at: Set(rt_expires),
            revoked_at: Set(None),
            revoke_reason: Set(None),
            replaced_by_id: Set(None),
        };
        if let Err(e) = new_rt.insert(&txn).await {
            tracing::error!("RT insert: {e}");
            return TokenEndpointResult::error(OAuth2ErrorCode::ServerError);
        }

        let mut rev: rt::ActiveModel = existing.into();
        rev.revoked_at = Set(Some(now));
        rev.revoke_reason = Set(Some("rotation".to_owned()));
        rev.replaced_by_id = Set(Some(new_rt_id));
        if let Err(e) = rev.update(&txn).await {
            tracing::error!("RT revoke: {e}");
            return TokenEndpointResult::error(OAuth2ErrorCode::ServerError);
        }

        if let Err(e) = txn.commit().await {
            tracing::error!("RT rotation transaction commit: {e}");
            return TokenEndpointResult::error(OAuth2ErrorCode::ServerError);
        }

        TokenEndpointResult::Success(TokenSuccessBody {
            access_token,
            token_type: "Bearer".to_owned(),
            expires_in: client.access_token_ttl_seconds as i64,
            refresh_token: Some(rt_raw_new),
            id_token: None,
            scope: scopes_str,
        })
    }
}
