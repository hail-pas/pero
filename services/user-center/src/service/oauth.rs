use pero_cache_redis::RedisCacheStore;
use pero_error::AppError;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DatabaseConnection, DbBackend, EntityTrait,
    QueryFilter, QuerySelect, Set, Statement, TransactionTrait,
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
use crate::db::enums::{CommonStatus, OauthClientType};
use crate::db::helper::{auth_code, auth_request};
use crate::state::session::SsoSession;

pub struct CreateAuthorizationRequestParams {
    pub client_id: Uuid,
    pub app_id: Uuid,
    pub tenant_id: Option<Uuid>,
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

        validate_client_parameters(&client, redirect_uri, scopes)?;
        Ok(client)
    }

    pub(crate) async fn validate_pending_authorization(
        &self,
        request: &authorization_requests::Model,
    ) -> Result<(), OAuthError> {
        let client = oauth_clients::Entity::find_by_id(request.client_id)
            .one(self.db)
            .await
            .map_err(|e| OAuthError::Internal(crate::db::error::to_app_error(e)))?
            .ok_or(OAuthError::AccessDenied)?;
        if !client_allows_authorization(&client, request) {
            return Err(OAuthError::AccessDenied);
        }
        self.validate_app(&client).await?;
        Ok(())
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
            + time::Duration::seconds(self.config.authorization_request_ttl_seconds as i64);

        auth_request::create(
            self.db,
            auth_request::CreateParams {
                diagnostic_session_id: None,
                client_id: params.client_id,
                app_id: params.app_id,
                tenant_id: params.tenant_id,
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

    /// An interactive request may activate existing organization eligibility.
    pub async fn ensure_app_access(
        &self,
        session: &SsoSession,
        app_id: Uuid,
    ) -> Result<bool, OAuthError> {
        crate::service::access::ensure_oauth_app_access(
            self.db,
            session,
            app_id,
            self.sso_config.session_idle_ttl_seconds,
        )
        .await
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
        confirm_takeover: bool,
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
        if !client_allows_authorization(&client, &request)
            || crate::service::access::lock_grant_access(&txn, session.user_id, request.app_id)
                .await
                .map_err(|e| OAuthError::Internal(crate::db::error::to_app_error(e)))?
                .is_none()
        {
            return Err(OAuthError::AccessDenied);
        }

        if crate::db::helper::session::app_query(
            OffsetDateTime::now_utc(),
            self.sso_config.session_idle_ttl_seconds,
            request.app_id,
        )
        .filter(crate::db::entity::sso_sessions::Column::Id.eq(session.id))
        .filter(crate::db::entity::sso_sessions::Column::UserId.eq(session.user_id))
        .lock_shared()
        .one(&txn)
        .await
        .map_err(|e| OAuthError::Internal(crate::db::error::to_app_error(e)))?
        .is_none()
        {
            return Err(OAuthError::AccessDenied);
        }

        if !super::tenant_context::lock_context(&txn, session.user_id, request.tenant_id)
            .await
            .map_err(|e| OAuthError::Internal(crate::db::error::to_app_error(e)))?
        {
            return Err(OAuthError::AccessDenied);
        }
        super::app_session::lock_devices(&txn, session.user_id, request.app_id, Some(session.id))
            .await
            .map_err(|e| OAuthError::Internal(crate::db::error::to_app_error(e)))?;

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

        if auth_request
            .diagnostic_session_id
            .is_some_and(|id| id != session.id)
        {
            return Err(OAuthError::AccessDenied);
        }

        let now = OffsetDateTime::now_utc();
        if auth_request.completed_at.is_some() || auth_request.expires_at <= now {
            return Err(OAuthError::AccessDenied);
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

        let system_app = apps::Entity::find_by_id(request.app_id)
            .one(&txn)
            .await
            .map_err(|e| OAuthError::Internal(crate::db::error::to_app_error(e)))?
            .is_some_and(|a| a.system);
        let tenant = if !system_app {
            Some(
                crate::service::tenant_context::resolve(
                    &txn,
                    session.user_id,
                    auth_request.app_id,
                    auth_request.tenant_id,
                )
                .await
                .map_err(|e| OAuthError::Internal(crate::db::error::to_app_error(e)))?
                .ok_or(OAuthError::AccessDenied)?,
            )
        } else {
            None
        };
        if auth_request.tenant_id != tenant.as_ref().map(|c| c.tenant_id) {
            return Err(OAuthError::AccessDenied);
        }
        let takeover_allowed = grant_consent
            && confirm_takeover
            && !has_prompt(auth_request.prompt.as_deref(), "none");
        if !takeover_allowed
            && super::app_session::needs_confirmation(
                &txn,
                session.user_id,
                auth_request.app_id,
                session.id,
                self.sso_config.session_idle_ttl_seconds,
            )
            .await
            .map_err(|e| OAuthError::Internal(crate::db::error::to_app_error(e)))?
        {
            return Err(OAuthError::InteractionRequired);
        }
        auth_code::create(
            &txn,
            auth_code::CreateParams {
                code_hash,
                authorization_request_id: Some(auth_request.id),
                user_id: session.user_id,
                app_id: auth_request.app_id,
                tenant,
                client_id: auth_request.client_id,
                session_id: session.id,
                takeover_allowed,
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

        if grant_consent && auth_request.diagnostic_session_id.is_none() {
            // A new approval adds consent, not an implicit withdrawal. Merge under
            // the conflict row lock so concurrent approvals cannot lose scopes.
            // The client policy is locked above; never retain disallowed scopes.
            txn.execute_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "INSERT INTO user_consents(user_id,client_id,scopes,granted_at) VALUES($1,$2,$3,$4)
                 ON CONFLICT(user_id,client_id) DO UPDATE SET
                 scopes=ARRAY(SELECT DISTINCT scope FROM unnest(user_consents.scopes || EXCLUDED.scopes) AS granted(scope)
                              WHERE scope=ANY($5::text[]) ORDER BY scope),
                 granted_at=EXCLUDED.granted_at",
                [
                    session.user_id.into(),
                    auth_request.client_id.into(),
                    auth_request.scopes.clone().into(),
                    now.into(),
                    client.scopes.clone().into(),
                ],
            ))
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

    /// Reject only this request; existing consent is withdrawn by explicit revocation.
    pub async fn deny_authorization_request(
        &self,
        auth_request_id: Uuid,
        session: &SsoSession,
    ) -> Result<(), OAuthError> {
        let now = OffsetDateTime::now_utc();
        let result = authorization_requests::Entity::update_many()
            .col_expr(
                authorization_requests::Column::CompletedAt,
                sea_orm::sea_query::Expr::value(Some(now)),
            )
            .col_expr(
                authorization_requests::Column::AuthorizedUserId,
                sea_orm::sea_query::Expr::value(Some(session.user_id)),
            )
            .filter(authorization_requests::Column::Id.eq(auth_request_id))
            .filter(authorization_requests::Column::CompletedAt.is_null())
            .filter(authorization_requests::Column::ExpiresAt.gt(now))
            .filter(
                sea_orm::Condition::any()
                    .add(authorization_requests::Column::DiagnosticSessionId.is_null())
                    .add(authorization_requests::Column::DiagnosticSessionId.eq(session.id)),
            )
            .exec(self.db)
            .await
            .map_err(|error| OAuthError::Internal(crate::db::error::to_app_error(error)))?;
        if result.rows_affected != 1 {
            return Err(OAuthError::AccessDenied);
        }
        Ok(())
    }

    /// 将 authorization_request ID 存入 Redis（短命 pending），返回 nonce 作为 cookie 值
    pub async fn store_pending_request(&self, auth_request_id: Uuid) -> Result<String, OAuthError> {
        let nonce = pero_utils::crypto::generate_nonce();
        let key = pending_req
            .key_with_ttl(
                Duration::from_secs(self.config.authorization_request_ttl_seconds),
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

fn validate_client_parameters(
    client: &oauth_clients::Model,
    redirect_uri: &str,
    scopes: &[String],
) -> Result<(), OAuthError> {
    if client.status != CommonStatus::Active {
        return Err(OAuthError::InvalidClient("Client is disabled"));
    }
    if !client.redirect_uris.iter().any(|uri| uri == redirect_uri)
        || pero_utils::redirect::validate_oauth_redirect_uri(
            redirect_uri,
            client.r#type == OauthClientType::Public,
        )
        .is_err()
    {
        return Err(OAuthError::InvalidRedirectUri);
    }
    if let Some(scope) = scopes
        .iter()
        .find(|scope| !crate::service::scope::contains(&client.scopes, scope))
    {
        return Err(OAuthError::InvalidScope(scope.clone()));
    }
    Ok(())
}

fn client_allows_authorization(
    client: &oauth_clients::Model,
    request: &authorization_requests::Model,
) -> bool {
    client.app_id == request.app_id
        && client
            .grant_types
            .iter()
            .any(|grant| grant == "authorization_code")
        && (request.code_challenge.is_some()
            || (!client.require_pkce && client.r#type != OauthClientType::Public))
        && validate_client_parameters(client, &request.redirect_uri, &request.scopes).is_ok()
}

#[derive(Debug)]
pub enum OAuthError {
    InvalidClient(&'static str),
    InvalidRedirectUri,
    InvalidScope(String),
    AccessDenied,
    InteractionRequired,
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
            OAuthError::InteractionRequired => {
                AppError::bad_request("interaction_required", "Device confirmation required")
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
