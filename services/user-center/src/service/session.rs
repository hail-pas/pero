use ipnetwork::IpNetwork;
use pero_error::AppError;
use sea_orm::{
    ColumnTrait, ConnectionTrait, DatabaseConnection, EntityTrait, ExprTrait, QueryFilter,
    TransactionTrait,
};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::config::SsoConfig;
use crate::db::entity::{refresh_tokens, sso_sessions, users};
use crate::db::enums::UserStatus;
use crate::db::helper::session as session_helper;
use crate::state::session::SsoSession;

pub struct SessionService<'a> {
    db: &'a DatabaseConnection,
    config: &'a SsoConfig,
}

struct CreateSession<'a> {
    user_id: Uuid,
    identity_id: Option<Uuid>,
    provider_id: Option<Uuid>,
    ip: Option<IpNetwork>,
    user_agent: Option<String>,
    verified: Option<&'a crate::db::entity::identities::Model>,
    authenticated_at: Option<OffsetDateTime>,
}

impl<'a> SessionService<'a> {
    pub fn new(db: &'a DatabaseConnection, config: &'a SsoConfig) -> Self {
        Self { db, config }
    }

    /// The database is authoritative for revocation. A joined read avoids a cache
    /// roundtrip followed by the same database checks on every cache hit.
    pub async fn validate(&self, token: &str) -> Result<Option<SsoSession>, AppError> {
        let token_hash = pero_utils::crypto::sha256_hex(token);
        let now = OffsetDateTime::now_utc();
        let row = session_helper::active_query(now, self.config.session_idle_ttl_seconds)
            .filter(sso_sessions::Column::TokenHash.eq(token_hash))
            .find_also_related(users::Entity)
            .one(self.db)
            .await
            .map_err(|e| {
                AppError::internal("session_query_failed", "Session query failed").with_source(e)
            })?;
        let Some((session, Some(user))) = row else {
            return Ok(None);
        };
        if user.deleted_at.is_some() || user.status != UserStatus::Active {
            return Ok(None);
        }
        if now - session.last_seen_at
            >= time::Duration::seconds(self.config.session_touch_interval_seconds as i64)
        {
            session_helper::touch_last_seen_after(
                self.db,
                session.id,
                self.config.session_touch_interval_seconds,
            )
            .await
            .map_err(|e| {
                AppError::internal("session_touch_failed", "Session update failed").with_source(e)
            })?;
        }
        Ok(Some(SsoSession {
            id: session.id,
            authenticated_at: session.authenticated_at,
            created_at: session.created_at,
            user_id: session.user_id,
            identity_id: session.identity_id,
        }))
    }

    /// 创建新 SSO session（数据库为唯一有效性来源），返回 (raw_token, session_id)
    pub async fn create(
        &self,
        user_id: Uuid,
        identity_id: Option<Uuid>,
        provider_id: Option<Uuid>,
        ip: Option<IpNetwork>,
        user_agent: Option<String>,
    ) -> Result<(String, Uuid), AppError> {
        self.create_checked(CreateSession {
            user_id,
            identity_id,
            provider_id,
            ip,
            user_agent,
            verified: None,
            authenticated_at: None,
        })
        .await
    }

    pub async fn create_verified_password(
        &self,
        identity: &crate::db::entity::identities::Model,
        ip: Option<IpNetwork>,
        user_agent: Option<String>,
    ) -> Result<(String, Uuid), AppError> {
        self.create_checked(CreateSession {
            user_id: identity.user_id,
            identity_id: Some(identity.id),
            provider_id: None,
            ip,
            user_agent,
            verified: Some(identity),
            authenticated_at: None,
        })
        .await
    }

    pub async fn create_social(
        &self,
        user_id: Uuid,
        identity_id: Uuid,
        provider_id: Uuid,
        ip: Option<IpNetwork>,
        authenticated_at: Option<OffsetDateTime>,
        user_agent: Option<String>,
    ) -> Result<(String, Uuid), AppError> {
        self.create_checked(CreateSession {
            user_id,
            identity_id: Some(identity_id),
            provider_id: Some(provider_id),
            ip,
            user_agent,
            verified: None,
            authenticated_at,
        })
        .await
    }

    async fn create_checked(&self, params: CreateSession<'_>) -> Result<(String, Uuid), AppError> {
        let CreateSession {
            user_id,
            identity_id,
            provider_id,
            ip,
            user_agent,
            verified,
            authenticated_at,
        } = params;
        let db_error = |e| {
            AppError::internal("session_create_failed", "Failed to create session").with_source(e)
        };
        let txn = self.db.begin().await.map_err(db_error)?;
        let user = crate::service::password::PasswordIdentityService::lock_user(&txn, user_id)
            .await
            .map_err(db_error)?;
        if user.status != UserStatus::Active {
            return Err(AppError::unauthorized("user_inactive", "User is inactive"));
        }
        if verified.is_none()
            && let Some(identity_id) = identity_id
            && crate::db::entity::identities::Entity::find_by_id(identity_id)
                .filter(crate::db::entity::identities::Column::UserId.eq(user_id))
                .filter(crate::db::entity::identities::Column::UnboundAt.is_null())
                .one(&txn)
                .await
                .map_err(db_error)?
                .is_none()
        {
            return Err(AppError::unauthorized(
                "credentials_changed",
                "Login identity is no longer bound",
            ));
        }
        if let Some(provider_id) = provider_id {
            crate::service::provider::require_enabled_social(&txn, provider_id).await?;
        }
        if let Some(verified) = verified {
            crate::service::password::PasswordIdentityService::ensure_unchanged(&txn, verified)
                .await
                .map_err(|_| {
                    AppError::unauthorized(
                        "credentials_changed",
                        "Credentials changed; authenticate again",
                    )
                })?;
        }
        let token = pero_utils::crypto::generate_token();
        let token_hash = pero_utils::crypto::sha256_hex(&token);
        let expires_at = OffsetDateTime::now_utc()
            + time::Duration::seconds(self.config.session_ttl_seconds as i64);
        // A local login proves fresh credentials. Upstream login proves their
        // age only when a validated OIDC auth_time is present.
        let credential_authenticated_at = if provider_id.is_none() {
            Some(OffsetDateTime::now_utc())
        } else {
            authenticated_at
        };

        let session = session_helper::create(
            &txn,
            session_helper::CreateParams {
                token_hash,
                user_id,
                identity_id,
                provider_id,
                ip,
                user_agent,
                expires_at,
                authenticated_at: authenticated_at.unwrap_or_else(OffsetDateTime::now_utc),
                reauthenticated_at: credential_authenticated_at,
            },
        )
        .await
        .map_err(|e| {
            AppError::internal("session_create_failed", "Failed to create session").with_source(e)
        })?;

        use sea_orm::{DbBackend, Statement};
        txn.execute_raw(Statement::from_sql_and_values(DbBackend::Postgres,
            "UPDATE sso_sessions SET mfa_required = (EXISTS(SELECT 1 FROM user_mfa WHERE user_id=$1 AND enabled) OR EXISTS(SELECT 1 FROM admin_roles WHERE user_id=$1)) WHERE id=$2",
            [user_id.into(), session.id.into()])).await.map_err(db_error)?;
        txn.commit().await.map_err(db_error)?;
        Ok((token, session.id))
    }

    pub async fn revoke_all_login_state_for_user_in_db<C>(
        db: &C,
        user_id: Uuid,
        reason: &str,
    ) -> Result<(), sea_orm::DbErr>
    where
        C: ConnectionTrait,
    {
        session_helper::revoke_all_for_user(db, user_id, Some(reason.to_owned())).await?;
        Self::revoke_refresh_tokens_where_on(db, reason, |query| {
            query.filter(refresh_tokens::Column::UserId.eq(user_id))
        })
        .await?;
        Ok(())
    }

    pub async fn revoke_login_state(&self, session_id: Uuid, reason: &str) -> Result<(), AppError> {
        let result: Result<(), sea_orm::DbErr> = async {
            let txn = self.db.begin().await?;
            session_helper::revoke(&txn, session_id, Some(reason.to_owned())).await?;
            Self::revoke_refresh_tokens_where_on(&txn, reason, |query| {
                query.filter(refresh_tokens::Column::SessionId.eq(session_id))
            })
            .await?;
            txn.commit().await?;
            Ok(())
        }
        .await;
        result.map_err(|e| {
            AppError::internal("session_revoke_failed", "Failed to revoke login state")
                .with_source(e)
        })?;
        Ok(())
    }

    pub async fn revoke_app_grants<C: ConnectionTrait>(
        db: &C,
        app_id: Uuid,
        user_id: Option<Uuid>,
        reason: &str,
    ) -> Result<(), sea_orm::DbErr> {
        use crate::db::entity::{
            authorization_codes as codes, authorization_requests as requests,
            user_app_access as access,
        };
        let grants = access::Entity::update_many()
            .col_expr(
                access::Column::TokenVersion,
                sea_orm::sea_query::Expr::col(access::Column::TokenVersion).add(1),
            )
            .filter(access::Column::AppId.eq(app_id));
        let grants = match user_id {
            Some(user) => grants.filter(access::Column::UserId.eq(user)),
            None => grants,
        };
        grants.exec(db).await?;
        Self::revoke_refresh_tokens_where_on(db, reason, |query| {
            let query = query.filter(refresh_tokens::Column::AppId.eq(app_id));
            match user_id {
                Some(user) => query.filter(refresh_tokens::Column::UserId.eq(user)),
                None => query,
            }
        })
        .await?;
        let codes = codes::Entity::delete_many()
            .filter(codes::Column::AppId.eq(app_id))
            .filter(codes::Column::ConsumedAt.is_null());
        let codes = match user_id {
            Some(user) => codes.filter(codes::Column::UserId.eq(user)),
            None => codes,
        };
        codes.exec(db).await?;
        let requests = requests::Entity::delete_many()
            .filter(requests::Column::AppId.eq(app_id))
            .filter(requests::Column::CompletedAt.is_null());
        let requests = match user_id {
            Some(user) => requests.filter(requests::Column::AuthorizedUserId.eq(user)),
            None => requests,
        };
        requests.exec(db).await?;
        Ok(())
    }

    pub async fn revoke_client_grants<C: ConnectionTrait>(
        db: &C,
        client_id: Uuid,
        reason: &str,
    ) -> Result<(), sea_orm::DbErr> {
        use crate::db::entity::{authorization_codes as codes, authorization_requests as requests};
        Self::revoke_refresh_tokens_where_on(db, reason, |query| {
            query.filter(refresh_tokens::Column::ClientId.eq(client_id))
        })
        .await?;
        codes::Entity::delete_many()
            .filter(codes::Column::ClientId.eq(client_id))
            .filter(codes::Column::ConsumedAt.is_null())
            .exec(db)
            .await?;
        requests::Entity::delete_many()
            .filter(requests::Column::ClientId.eq(client_id))
            .filter(requests::Column::CompletedAt.is_null())
            .exec(db)
            .await?;
        Ok(())
    }

    async fn revoke_refresh_tokens_where_on<C, F>(
        db: &C,
        reason: &str,
        apply_filters: F,
    ) -> Result<(), sea_orm::DbErr>
    where
        C: ConnectionTrait,
        F: FnOnce(
            sea_orm::UpdateMany<refresh_tokens::Entity>,
        ) -> sea_orm::UpdateMany<refresh_tokens::Entity>,
    {
        let now = OffsetDateTime::now_utc();
        let query = refresh_tokens::Entity::update_many()
            .col_expr(
                refresh_tokens::Column::RevokedAt,
                sea_orm::sea_query::Expr::value(Some(now)),
            )
            .col_expr(
                refresh_tokens::Column::RevokeReason,
                sea_orm::sea_query::Expr::value(Some(reason.to_owned())),
            )
            // Policy revocation also retires rotation predecessors, so an old
            // token cannot turn an app-only withdrawal into SSO-wide logout.
            .filter(
                refresh_tokens::Column::RevokedAt
                    .is_null()
                    .or(refresh_tokens::Column::RevokeReason.eq("rotation")),
            );

        apply_filters(query).exec(db).await?;
        Ok(())
    }
}
