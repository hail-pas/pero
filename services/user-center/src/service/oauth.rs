use pero_cache_redis::RedisCacheStore;
use pero_error::AppError;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QuerySelect, Set,
    TransactionTrait,
};
use std::time::Duration;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::cache::{PendingReqValue, pending_req};
use crate::config::{OAuth2Config, SsoConfig};
use crate::db::entity::apps;
use crate::db::entity::authorization_requests;
use crate::db::entity::oauth_clients;
use crate::db::entity::user_consents;
use crate::db::enums::CommonStatus;
use crate::db::helper::{auth_code, auth_request};
use crate::state::session::SsoSession;

pub struct CreateAuthorizationRequestParams {
    pub client_id: Uuid,
    pub app_id: Uuid,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub client_state: Option<String>,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<crate::db::enums::CodeChallengeMethod>,
    pub prompt: Option<String>,
    pub max_age: Option<i64>,
    pub login_hint: Option<String>,
}

pub struct OAuthService<'a> {
    db: &'a DatabaseConnection,
    cache: &'a RedisCacheStore,
    config: &'a OAuth2Config,
    sso_config: &'a SsoConfig,
}

impl<'a> OAuthService<'a> {
    pub fn new(
        db: &'a DatabaseConnection,
        cache: &'a RedisCacheStore,
        config: &'a OAuth2Config,
        sso_config: &'a SsoConfig,
    ) -> Self {
        Self {
            db,
            cache,
            config,
            sso_config,
        }
    }

    /// 校验 OAuth2 客户端：identifier 查找 → 状态检查 → redirect_uri 白名单 → scope 白名单
    pub async fn validate_client(
        &self,
        client_identifier: &str,
        redirect_uri: &str,
        scopes: &[String],
    ) -> Result<oauth_clients::Model, OAuthError> {
        let client = oauth_clients::Entity::find()
            .filter(oauth_clients::Column::Identifier.eq(client_identifier))
            .one(self.db)
            .await
            .map_err(|e| OAuthError::Internal(crate::db::error::to_app_error(e)))?;

        let client = client.ok_or(OAuthError::InvalidClient("Client not found"))?;

        if client.status != CommonStatus::Active {
            return Err(OAuthError::InvalidClient("Client is disabled"));
        }

        if !client.redirect_uris.iter().any(|uri| uri == redirect_uri) {
            return Err(OAuthError::InvalidRedirectUri);
        }
        if pero_utils::redirect::validate_oauth_redirect_uri(redirect_uri).is_err() {
            return Err(OAuthError::InvalidRedirectUri);
        }

        for scope in scopes {
            if !crate::service::scope::contains(&client.scopes, scope) {
                return Err(OAuthError::InvalidScope(scope.clone()));
            }
        }

        Ok(client)
    }

    /// 校验客户端关联的 App 是否存在且 active
    pub async fn validate_app(
        &self,
        client: &oauth_clients::Model,
    ) -> Result<apps::Model, OAuthError> {
        let app = apps::Entity::find_by_id(client.app_id)
            .one(self.db)
            .await
            .map_err(|e| OAuthError::Internal(crate::db::error::to_app_error(e)))?
            .ok_or(OAuthError::InvalidClient("App not found"))?;

        if app.status != CommonStatus::Active {
            return Err(OAuthError::InvalidClient("App is disabled"));
        }

        Ok(app)
    }

    /// 创建 authorization_request 记录（DB.W），用于追踪整个授权流程状态
    pub async fn create_authorization_request(
        &self,
        params: CreateAuthorizationRequestParams,
    ) -> Result<authorization_requests::Model, OAuthError> {
        let expires_at = OffsetDateTime::now_utc()
            + time::Duration::seconds(self.config.auth_code_ttl_seconds as i64);

        auth_request::create(
            self.db,
            auth_request::CreateParams {
                client_id: params.client_id,
                app_id: params.app_id,
                redirect_uri: params.redirect_uri,
                scopes: params.scopes,
                client_state: params.client_state,
                nonce: params.nonce,
                code_challenge: params.code_challenge,
                code_challenge_method: params.code_challenge_method,
                prompt: params.prompt,
                max_age: params.max_age,
                login_hint: params.login_hint,
                expires_at,
            },
        )
        .await
        .map_err(|e| OAuthError::Internal(crate::db::error::to_app_error(e)))
    }

    /// 检查用户是否有权访问该 App（user_app_access 表 status=active）
    pub async fn check_app_access(&self, user_id: Uuid, app_id: Uuid) -> Result<bool, OAuthError> {
        crate::service::access::active_app_access(self.db, user_id, app_id)
            .await
            .map(|access| access.is_some())
            .map_err(|e| OAuthError::Internal(crate::db::error::to_app_error(e)))
    }

    /// 检查用户是否已同意所有请求的 scope（user_consents 表）
    pub async fn check_consent(
        &self,
        user_id: Uuid,
        client_id: Uuid,
        requested_scopes: &[String],
    ) -> Result<bool, OAuthError> {
        let consent = user_consents::Entity::find_by_id((user_id, client_id))
            .one(self.db)
            .await
            .map_err(|e| OAuthError::Internal(crate::db::error::to_app_error(e)))?;

        let Some(consent) = consent else {
            return Ok(false);
        };

        for scope in requested_scopes {
            if !crate::service::scope::contains(&consent.scopes, scope) {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// 签发 authorization code，可选写入 consent，标记 auth_request 完成
    ///
    /// 事务内：SELECT FOR LOCK → INSERT auth_code → (可选) UPSERT consent → UPDATE completed_at → commit
    pub async fn issue_auth_code_with_consent(
        &self,
        auth_request_id: Uuid,
        session: &SsoSession,
        grant_consent: bool,
    ) -> Result<String, OAuthError> {
        let raw_code = pero_utils::crypto::generate_token();
        let code_hash = pero_utils::crypto::sha256_hex(&raw_code);
        let expires_at = OffsetDateTime::now_utc()
            + time::Duration::seconds(self.config.auth_code_ttl_seconds as i64);

        let txn = self
            .db
            .begin()
            .await
            .map_err(|e| OAuthError::Internal(crate::db::error::to_app_error(e)))?;

        // Read the owner without locking the request. All grant paths acquire
        // client -> app -> access -> user policy locks before a grant/request lock.
        let request = authorization_requests::Entity::find_by_id(auth_request_id)
            .one(&txn)
            .await
            .map_err(|e| OAuthError::Internal(crate::db::error::to_app_error(e)))?
            .ok_or(OAuthError::AccessDenied)?;
        let client = oauth_clients::Entity::find_by_id(request.client_id)
            .lock_shared()
            .one(&txn)
            .await
            .map_err(|e| OAuthError::Internal(crate::db::error::to_app_error(e)))?
            .ok_or(OAuthError::AccessDenied)?;
        if client.status != CommonStatus::Active
            || client.app_id != request.app_id
            || !client
                .grant_types
                .iter()
                .any(|grant| grant == "authorization_code")
            || !client.redirect_uris.contains(&request.redirect_uri)
            || !crate::service::scope::allowed(&request.scopes, &client.scopes)
            || crate::service::access::lock_grant_access(&txn, session.user_id, request.app_id)
                .await
                .map_err(|e| OAuthError::Internal(crate::db::error::to_app_error(e)))?
                .is_none()
        {
            return Err(OAuthError::AccessDenied);
        }

        if crate::db::helper::session::lock_active(
            &txn,
            session.id,
            session.user_id,
            self.sso_config.session_idle_ttl_seconds,
        )
        .await
        .map_err(|e| OAuthError::Internal(crate::db::error::to_app_error(e)))?
        .is_none()
        {
            return Err(OAuthError::AccessDenied);
        }

        if !grant_consent {
            let consent = user_consents::Entity::find_by_id((session.user_id, client.id))
                .one(&txn)
                .await
                .map_err(|e| OAuthError::Internal(crate::db::error::to_app_error(e)))?;
            if !consent.is_some_and(|consent| {
                crate::service::scope::allowed(&request.scopes, &consent.scopes)
            }) {
                return Err(OAuthError::AccessDenied);
            }
        }
        let auth_request = authorization_requests::Entity::find_by_id(auth_request_id)
            .lock_exclusive()
            .one(&txn)
            .await
            .map_err(|e| OAuthError::Internal(crate::db::error::to_app_error(e)))?
            .ok_or_else(|| {
                OAuthError::Internal(AppError::bad_request(
                    "invalid_authorization_request",
                    "Authorization request not found",
                ))
            })?;

        let now = OffsetDateTime::now_utc();
        if auth_request.completed_at.is_some() || auth_request.expires_at < now {
            return Err(OAuthError::Internal(AppError::bad_request(
                "invalid_authorization_request",
                "Authorization request is no longer valid",
            )));
        }

        if requires_reauthentication(
            auth_request.prompt.as_deref(),
            auth_request.max_age,
            session.authenticated_at,
            session.created_at,
            auth_request.created_at,
            now,
        ) {
            return Err(OAuthError::AccessDenied);
        }

        auth_code::create(
            &txn,
            auth_code::CreateParams {
                code_hash,
                authorization_request_id: Some(auth_request.id),
                user_id: session.user_id,
                app_id: auth_request.app_id,
                client_id: auth_request.client_id,
                session_id: session.id,
                redirect_uri: auth_request.redirect_uri.clone(),
                scopes: auth_request.scopes.clone(),
                nonce: auth_request.nonce.clone(),
                code_challenge: auth_request.code_challenge.clone(),
                code_challenge_method: auth_request.code_challenge_method.clone(),
                expires_at,
            },
        )
        .await
        .map_err(|e| OAuthError::Internal(crate::db::error::to_app_error(e)))?;

        if grant_consent {
            user_consents::Entity::insert(user_consents::ActiveModel {
                user_id: Set(session.user_id),
                client_id: Set(auth_request.client_id),
                scopes: Set(auth_request.scopes.clone()),
                granted_at: Set(now),
            })
            .on_conflict(
                sea_orm::sea_query::OnConflict::columns([
                    user_consents::Column::UserId,
                    user_consents::Column::ClientId,
                ])
                .update_columns([
                    user_consents::Column::Scopes,
                    user_consents::Column::GrantedAt,
                ])
                .to_owned(),
            )
            .exec(&txn)
            .await
            .map_err(|e| OAuthError::Internal(crate::db::error::to_app_error(e)))?;
        }

        let mut active: authorization_requests::ActiveModel = auth_request.into();
        active.completed_at = Set(Some(now));
        active.authorized_user_id = Set(Some(session.user_id));
        active
            .update(&txn)
            .await
            .map_err(|e| OAuthError::Internal(crate::db::error::to_app_error(e)))?;

        txn.commit()
            .await
            .map_err(|e| OAuthError::Internal(crate::db::error::to_app_error(e)))?;

        Ok(raw_code)
    }

    /// A request has one terminal decision. Claim it before changing stored consent.
    pub async fn deny_authorization_request(
        &self,
        auth_request_id: Uuid,
        user_id: Uuid,
    ) -> Result<(), OAuthError> {
        let result: Result<(), sea_orm::DbErr> = async {
            let txn = self.db.begin().await?;
            let now = OffsetDateTime::now_utc();
            let request = authorization_requests::Entity::update_many()
                .col_expr(
                    authorization_requests::Column::CompletedAt,
                    sea_orm::sea_query::Expr::value(Some(now)),
                )
                .col_expr(
                    authorization_requests::Column::AuthorizedUserId,
                    sea_orm::sea_query::Expr::value(Some(user_id)),
                )
                .filter(authorization_requests::Column::Id.eq(auth_request_id))
                .filter(authorization_requests::Column::CompletedAt.is_null())
                .filter(authorization_requests::Column::ExpiresAt.gt(now))
                .exec_with_returning(&txn)
                .await?;
            let Some(request) = request.first() else {
                return Err(sea_orm::DbErr::RecordNotFound(
                    "Authorization request is no longer valid".into(),
                ));
            };
            user_consents::Entity::delete_by_id((user_id, request.client_id))
                .exec(&txn)
                .await?;
            txn.commit().await
        }
        .await;
        result.map_err(|error| match error {
            sea_orm::DbErr::RecordNotFound(_) => OAuthError::AccessDenied,
            error => OAuthError::Internal(crate::db::error::to_app_error(error)),
        })
    }

    /// 将 authorization_request ID 存入 Redis（短命 pending），返回 nonce 作为 cookie 值
    pub async fn store_pending_request(&self, auth_request_id: Uuid) -> Result<String, OAuthError> {
        let nonce = pero_utils::crypto::generate_nonce();
        let key = pending_req
            .key_with_ttl(
                Duration::from_secs(self.config.auth_code_ttl_seconds),
                &nonce,
            )
            .map_err(|e| {
                OAuthError::Internal(
                    AppError::internal("cache_key_error", "cache key error").with_source(e),
                )
            })?;

        self.cache
            .set(
                key,
                &PendingReqValue {
                    auth_request_id: auth_request_id.to_string(),
                },
            )
            .await
            .map_err(OAuthError::Internal)?;

        Ok(nonce)
    }

    pub async fn pending_request_requires_login(
        &self,
        nonce: &str,
        session: &SsoSession,
    ) -> Result<bool, AppError> {
        let Some(value) = self.cache.get(pending_req.key(nonce)?).await? else {
            return Ok(false);
        };
        let id = Uuid::parse_str(&value.auth_request_id).map_err(|_| {
            AppError::bad_request("invalid_pending_request", "Invalid pending request")
        })?;
        let request = authorization_requests::Entity::find_by_id(id)
            .one(self.db)
            .await
            .map_err(crate::db::error::to_app_error)?;
        Ok(request.is_some_and(|request| {
            requires_reauthentication(
                request.prompt.as_deref(),
                request.max_age,
                session.authenticated_at,
                session.created_at,
                request.created_at,
                OffsetDateTime::now_utc(),
            )
        }))
    }

    /// 消费 pending request（Redis GETDEL），返回 authorization_request ID
    pub async fn consume_pending_request(&self, nonce: &str) -> Result<Option<Uuid>, AppError> {
        let key = pending_req.key(nonce)?;
        let value = self.cache.take(key).await?;
        let Some(value) = value else {
            return Ok(None);
        };
        Uuid::parse_str(&value.auth_request_id)
            .map(Some)
            .map_err(|e| {
                AppError::bad_request("invalid_pending_request", "Invalid pending request")
                    .with_source(e)
            })
    }

    pub async fn has_pending_request(&self, nonce: &str) -> Result<bool, AppError> {
        let key = pending_req.key(nonce)?;
        let value: Option<PendingReqValue> = self.cache.get(key).await?;
        Ok(value.is_some())
    }
}

#[derive(Debug)]
pub enum OAuthError {
    InvalidClient(&'static str),
    InvalidRedirectUri,
    InvalidScope(String),
    AccessDenied,
    Internal(AppError),
}

impl From<OAuthError> for AppError {
    fn from(value: OAuthError) -> Self {
        match value {
            OAuthError::InvalidClient(msg) => AppError::bad_request("invalid_client", msg),
            OAuthError::InvalidRedirectUri => {
                AppError::bad_request("invalid_redirect_uri", "Redirect URI not allowed")
            }
            OAuthError::InvalidScope(scope) => {
                AppError::bad_request("invalid_scope", format!("Scope '{}' not allowed", scope))
            }
            OAuthError::AccessDenied => {
                AppError::forbidden("access_denied", "Access denied to this application")
            }
            OAuthError::Internal(e) => e,
        }
    }
}

pub fn has_prompt(prompt: Option<&str>, expected: &str) -> bool {
    prompt.is_some_and(|p| p.split_whitespace().any(|value| value == expected))
}

pub fn requires_reauthentication(
    prompt: Option<&str>,
    max_age: Option<i64>,
    authenticated_at: OffsetDateTime,
    session_created_at: OffsetDateTime,
    requested_at: OffsetDateTime,
    now: OffsetDateTime,
) -> bool {
    if (has_prompt(prompt, "login") || max_age == Some(0))
        && (session_created_at < requested_at
            || authenticated_at.unix_timestamp() < requested_at.unix_timestamp())
    {
        return true;
    }
    max_age.is_some_and(|age| {
        age > 0
            && now
                .unix_timestamp()
                .saturating_sub(authenticated_at.unix_timestamp())
                > age
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn authentication_age_is_enforced_without_reauthenticating_a_fresh_zero_age_flow() {
        let request = OffsetDateTime::now_utc();
        let old = request - time::Duration::seconds(60);
        let fresh = request + time::Duration::seconds(1);
        assert!(requires_reauthentication(
            Some("login consent"),
            None,
            old,
            old,
            request,
            request
        ));
        assert!(requires_reauthentication(
            None,
            Some(0),
            old,
            old,
            request,
            request
        ));
        assert!(requires_reauthentication(
            Some("none"),
            Some(10),
            old,
            old,
            request,
            request
        ));
        assert!(!requires_reauthentication(
            None,
            Some(60),
            old,
            old,
            request,
            request
        ));
        assert!(!requires_reauthentication(
            Some("login"),
            Some(0),
            fresh,
            fresh,
            request,
            fresh + time::Duration::seconds(10)
        ));
        assert!(!requires_reauthentication(
            None, None, old, old, request, request
        ));
        assert!(requires_reauthentication(
            None,
            Some(1),
            fresh,
            fresh,
            request,
            fresh + time::Duration::seconds(2)
        ));
    }
}
