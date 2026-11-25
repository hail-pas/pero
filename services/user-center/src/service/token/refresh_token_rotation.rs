use pero_api_axum::oauth::TokenSuccessBody;
use pero_error::protocol::oauth::OAuth2ErrorCode;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, QuerySelect, Set, TransactionTrait,
};

use super::token_issuer::TokenIssuer;
use super::{TokenEndpointResult, TokenRequest, TokenService};
use crate::db::entity::oauth_clients as oc;

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
            .column(rt::Column::SessionId)
            .column(rt::Column::TenantId)
            .into_tuple::<(uuid::Uuid, uuid::Uuid, Option<uuid::Uuid>, Option<uuid::Uuid>)>()
            .one(&txn)
            .await;
        let (user_id, app_id, session_id, tenant_id) = match owner {
            Ok(Some(owner)) => owner,
            Ok(None) => return TokenEndpointResult::error(OAuth2ErrorCode::InvalidGrant),
            Err(_) => return TokenEndpointResult::error(OAuth2ErrorCode::ServerError),
        };
        let access = match crate::service::access::lock_grant_access(&txn, user_id, app_id).await {
            Ok(Some(access)) => access,
            Ok(None) => return TokenEndpointResult::error(OAuth2ErrorCode::InvalidGrant),
            Err(_) => return TokenEndpointResult::error(OAuth2ErrorCode::ServerError),
        };

        // Lock the session before the grant row: logout updates the session first,
        // then revokes refresh tokens and queues backchannel notifications.
        let Some(session_id) = session_id else {
            return TokenEndpointResult::error(OAuth2ErrorCode::InvalidGrant);
        };
        let _active_session = match crate::db::helper::session::app_query(
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
            Ok(None) => return TokenEndpointResult::error(OAuth2ErrorCode::InvalidGrant),
            Err(_) => return TokenEndpointResult::error(OAuth2ErrorCode::ServerError),
        };

        match crate::service::tenant_context::lock_context(&txn, user_id, tenant_id).await {
            Ok(true) => {}
            Ok(false) => return TokenEndpointResult::error(OAuth2ErrorCode::InvalidGrant),
            Err(_) => return TokenEndpointResult::error(OAuth2ErrorCode::ServerError),
        }
        if crate::service::app_session::lock_devices(&txn, user_id, app_id, Some(session_id))
            .await
            .is_err()
        {
            return TokenEndpointResult::error(OAuth2ErrorCode::ServerError);
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
        let Some(client_session_id) = existing.client_session_id else {
            return TokenEndpointResult::error(OAuth2ErrorCode::InvalidGrant);
        };
        match crate::service::app_session::sso_for_client(
            &txn,
            client_session_id,
            user_id,
            client.id,
            app_id,
            existing.tenant_id,
        )
        .await
        {
            Ok(Some(id)) if id == session_id => {}
            Ok(_) => return TokenEndpointResult::error(OAuth2ErrorCode::InvalidGrant),
            Err(_) => return TokenEndpointResult::error(OAuth2ErrorCode::ServerError),
        }
        if existing.revoked_at.is_some() {
            // Explicit withdrawal is not evidence of a rotation replay.
            if existing.revoke_reason.as_deref() != Some("rotation") {
                return TokenEndpointResult::error_desc(
                    OAuth2ErrorCode::InvalidGrant,
                    "Refresh token revoked",
                );
            }
            // Tenant policy changes also invalidate rotation predecessors. Do not
            // turn a withdrawn tenant grant into a logout across applications.
            match crate::service::tenant_context::grant_context_is_current(
                &txn,
                existing.user_id,
                existing.app_id,
                existing.tenant_id,
                existing.tenant_version,
                existing.tenant_member_version,
            )
            .await
            {
                Ok(true) => {}
                Ok(false) => return TokenEndpointResult::error(OAuth2ErrorCode::InvalidGrant),
                Err(_) => return TokenEndpointResult::error(OAuth2ErrorCode::ServerError),
            }
            if let Err(error) = crate::service::app_session::revoke_client(
                &txn,
                client_session_id,
                existing.user_id,
                client.id,
                "refresh_token_reuse",
            )
            .await
            {
                tracing::error!(%error, "Refresh token replay revocation failed");
                return TokenEndpointResult::error(OAuth2ErrorCode::TemporarilyUnavailable);
            }
            if let Err(error) = txn.commit().await {
                tracing::error!(%error, "Refresh token replay commit failed");
                return TokenEndpointResult::error(OAuth2ErrorCode::TemporarilyUnavailable);
            }
            return TokenEndpointResult::error_desc(
                OAuth2ErrorCode::InvalidGrant,
                "Refresh token revoked",
            );
        }
        let now = time::OffsetDateTime::now_utc();
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

        let user = &access.user;
        let tenant = if let Some(id) = existing.tenant_id {
            let ctx = match crate::service::tenant_context::active(&txn, user.id, client.app_id, id)
                .await
            {
                Ok(Some(ctx)) => ctx,
                Ok(None) => return TokenEndpointResult::error(OAuth2ErrorCode::InvalidGrant),
                Err(_) => return TokenEndpointResult::error(OAuth2ErrorCode::ServerError),
            };
            if Some(ctx.tenant_version) != existing.tenant_version
                || Some(ctx.tenant_member_version) != existing.tenant_member_version
            {
                return TokenEndpointResult::error(OAuth2ErrorCode::InvalidGrant);
            }
            Some(ctx)
        } else {
            None
        };
        if !access.app.system && tenant.is_none() {
            return TokenEndpointResult::error(OAuth2ErrorCode::InvalidGrant);
        }
        let requested =
            match crate::service::scope::refresh_scopes(form.scope.as_deref(), &existing.scopes) {
                Some(scopes) => scopes,
                None => return TokenEndpointResult::error(OAuth2ErrorCode::InvalidScope),
            };
        let scopes_str = requested.join(" ");
        let session_id = Some(session_id);
        let signing = match require_active_signing_key(
            &txn,
            i64::from(client.access_token_ttl_seconds),
        )
        .await
        {
            Ok(k) => k,
            Err(_) => return TokenEndpointResult::error(OAuth2ErrorCode::ServerError),
        };

        let issuer = TokenIssuer::new(self.state, client, &signing);
        let access_token = match issuer.issue_access_token(
            user.id,
            &scopes_str,
            Some(client_session_id),
            access.token_version,
            tenant.as_ref(),
        ) {
            Ok(t) => t,
            Err(e) => {
                tracing::error!("AT sign: {e}");
                return TokenEndpointResult::error(OAuth2ErrorCode::ServerError);
            }
        };

        // Recheck expiry after policy and signing-key lookups, using the rotation time.
        let now = time::OffsetDateTime::now_utc();
        if existing.expires_at <= now {
            return TokenEndpointResult::error_desc(
                OAuth2ErrorCode::InvalidGrant,
                "Refresh token expired",
            );
        }
        let rt_raw_new = pero_utils::crypto::generate_token();
        let rt_hash_new = pero_utils::crypto::sha256_hex(&rt_raw_new);
        let rt_expires = now + time::Duration::seconds(client.refresh_token_ttl_seconds as i64);
        let new_rt_id = uuid::Uuid::now_v7();
        let new_rt = rt::ActiveModel {
            id: Set(new_rt_id),
            token_hash: Set(rt_hash_new),
            user_id: Set(existing.user_id),
            app_id: Set(existing.app_id),
            tenant_id: Set(existing.tenant_id),
            tenant_version: Set(existing.tenant_version),
            tenant_member_version: Set(existing.tenant_member_version),
            client_id: Set(client.id),
            session_id: Set(session_id),
            client_session_id: Set(Some(client_session_id)),
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
