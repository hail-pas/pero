use ipnetwork::IpNetwork;
use pero_cache_redis::RedisCacheStore;
use pero_cache_redis::rate_limit::{RateLimitError, enforce_rate_limit, rate_limit_check};
use pero_cache_redis::rate_limit_key::{login_fail, rl_login_account, rl_login_ip};
use sea_orm::{ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, Set};
use uuid::Uuid;

use crate::db::entity::{identities, users};
use crate::db::enums::{IdentityKind, LoginEventType};

pub struct PasswordLoginResult {
    pub user: users::Model,
    pub token: String,
}

pub enum PasswordLoginError {
    RateLimited,
    ServiceUnavailable,
    InvalidCredentials,
    AccountLocked,
    InternalError(String),
}

pub struct LoginService<'a> {
    db: &'a DatabaseConnection,
    cache: &'a RedisCacheStore,
}

impl<'a> LoginService<'a> {
    pub fn new(db: &'a DatabaseConnection, cache: &'a RedisCacheStore) -> Self {
        Self { db, cache }
    }

    pub async fn check_rate_limit(
        &self,
        ip: Option<IpNetwork>,
        account: &str,
    ) -> Result<(), PasswordLoginError> {
        let ip_str = ip.map(|v| v.to_string()).unwrap_or_else(|| {
            pero_config::blocks::ServerConfig::unknown_ip_placeholder().to_owned()
        });

        if let Ok(key) = rl_login_ip.key(&ip_str) {
            map_rate_limit_result(enforce_rate_limit(self.cache, &key, 20).await)?;
        }

        let account_key = pero_utils::string::canonical_rate_limit_key(account);
        if !account_key.is_empty()
            && let Ok(key) = rl_login_account.key(&account_key)
        {
            map_rate_limit_result(enforce_rate_limit(self.cache, &key, 20).await)?;
        }

        Ok(())
    }

    pub async fn is_account_locked(&self, user_id: Uuid) -> Result<bool, PasswordLoginError> {
        let key = login_fail
            .key(&user_id.to_string())
            .map_err(|_| PasswordLoginError::ServiceUnavailable)?;
        self.cache
            .get::<u32>(key)
            .await
            .map(|count| count.is_some_and(|count| count >= 5))
            .map_err(|e| {
                tracing::error!(error = %e, "Login lock lookup failed");
                PasswordLoginError::ServiceUnavailable
            })
    }

    pub async fn incr_failure(&self, user_id: Uuid) {
        if let Ok(key) = login_fail.key(&user_id.to_string())
            && let Err(e) = rate_limit_check(self.cache, &key, 99).await
        {
            tracing::warn!(error = %e, user_id = %user_id, "failed to increment login failure counter");
        }
    }

    pub async fn clear_failures(&self, user_id: Uuid) {
        if let Ok(key) = login_fail.key(&user_id.to_string()) {
            let _ = self.cache.del(key).await;
        }
    }

    pub async fn find_password_identity(
        &self,
        user_id: Uuid,
    ) -> Result<Option<identities::Model>, PasswordLoginError> {
        identities::Entity::find()
            .filter(identities::Column::UserId.eq(user_id))
            .filter(identities::Column::Kind.eq(IdentityKind::Password))
            .filter(identities::Column::UnboundAt.is_null())
            .one(self.db)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Password identity lookup failed");
                PasswordLoginError::ServiceUnavailable
            })
    }

    pub async fn update_identity_last_login(&self, identity_id: Uuid) {
        let Ok(Some(model)) = identities::Entity::find_by_id(identity_id)
            .one(self.db)
            .await
        else {
            return;
        };
        let mut active: identities::ActiveModel = model.into();
        active.last_login_at = Set(Some(time::OffsetDateTime::now_utc()));
        if let Err(e) = active.update(self.db).await {
            tracing::warn!("Identity last_login_at update: {e}");
        }
    }

    pub async fn record_failure(
        &self,
        user_id: Uuid,
        identity_id: Option<Uuid>,
        provider_id: Option<Uuid>,
        ip: Option<IpNetwork>,
    ) {
        let _ = crate::db::helper::login_event::record(
            self.db,
            crate::db::helper::login_event::RecordParams {
                user_id: Some(user_id),
                identity_id,
                provider_id,
                event_type: LoginEventType::LoginFailure,
                ip,
                user_agent: None,
                detail: serde_json::json!({}),
            },
        )
        .await;
    }

    pub async fn record_success(
        &self,
        user_id: Uuid,
        identity_id: Uuid,
        provider_id: Option<Uuid>,
        ip: Option<IpNetwork>,
        detail: serde_json::Value,
    ) {
        let _ = crate::db::helper::login_event::record(
            self.db,
            crate::db::helper::login_event::RecordParams {
                user_id: Some(user_id),
                identity_id: Some(identity_id),
                provider_id,
                event_type: LoginEventType::LoginSuccess,
                ip,
                user_agent: None,
                detail,
            },
        )
        .await;
    }

    pub async fn password_login(
        &self,
        session_svc: &crate::service::session::SessionService<'_>,
        ip: Option<IpNetwork>,
        identifier_type: &str,
        identifier: &str,
        password: &str,
    ) -> Result<PasswordLoginResult, PasswordLoginError> {
        let identifier = identifier.trim();
        self.check_rate_limit(ip, identifier).await?;

        let user =
            match crate::db::helper::user::find_by_identifier(self.db, identifier_type, identifier)
                .await
            {
                Ok(Some(u)) => u,
                Ok(None) => return Err(PasswordLoginError::InvalidCredentials),
                Err(e) => {
                    tracing::error!("User query error: {e}");
                    return Err(PasswordLoginError::InternalError(e.to_string()));
                }
            };

        if self.is_account_locked(user.id).await? {
            self.record_failure(user.id, None, None, ip).await;
            return Err(PasswordLoginError::AccountLocked);
        }

        let identity = match self.find_password_identity(user.id).await? {
            Some(id) => id,
            None => {
                self.record_failure(user.id, None, None, ip).await;
                return Err(PasswordLoginError::InvalidCredentials);
            }
        };

        if !crate::service::password::PasswordIdentityService::verify_password_hash(
            password,
            identity.password_hash.as_deref(),
        )
        .await
        .map_err(|_| PasswordLoginError::ServiceUnavailable)?
        {
            self.incr_failure(user.id).await;
            self.record_failure(user.id, Some(identity.id), None, ip)
                .await;
            return Err(PasswordLoginError::InvalidCredentials);
        }

        let (token, _session_id) = session_svc
            .create_verified_password(&identity, ip)
            .await
            .map_err(|e| {
                tracing::error!("Session create error: {e}");
                PasswordLoginError::InternalError(e.to_string())
            })?;

        self.clear_failures(user.id).await;
        self.update_identity_last_login(identity.id).await;
        self.record_success(user.id, identity.id, None, ip, serde_json::json!({}))
            .await;

        Ok(PasswordLoginResult { user, token })
    }
}

fn map_rate_limit_result(result: Result<(), RateLimitError>) -> Result<(), PasswordLoginError> {
    match result {
        Ok(()) => Ok(()),
        Err(RateLimitError::Denied { .. }) => Err(PasswordLoginError::RateLimited),
        Err(RateLimitError::Redis(e)) => {
            tracing::error!(error = %e, "rate_limit_check redis error");
            Err(PasswordLoginError::ServiceUnavailable)
        }
    }
}
