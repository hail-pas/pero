use super::*;
use pero_cache_redis::RedisCacheStore;
use pero_http_client_core::HttpClientExt;
use pero_http_client_core::HttpClientHandle;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
use std::time::Duration;
use uuid::Uuid;

use crate::cache::key::social_state;
use crate::db::entity::{identities, identity_providers as ip, users};
use crate::db::enums::{IdentityProviderKind, UserStatus};
use crate::db::helper::provider::{ProviderWithSecret, find_provider_with_secret};

impl<'a> SocialLoginService<'a> {
    pub fn new(
        db: &'a DatabaseConnection,
        cache: &'a RedisCacheStore,
        http_client: &'a HttpClientHandle,
        sso_config: &'a crate::config::SsoConfig,
        oauth2_config: &'a crate::config::OAuth2Config,
        jwks: &'a super::JwksCache,
        notification: &'a crate::config::NotificationConfig,
    ) -> Self {
        Self {
            db,
            cache,
            http_client,
            sso_config,
            oauth2_config,
            jwks,
            notification,
        }
    }

    fn adapter_for(kind: &IdentityProviderKind) -> Box<dyn adapter::SocialProviderAdapter> {
        match kind {
            IdentityProviderKind::Oauth2 | IdentityProviderKind::Oidc => {
                Box::new(oauth2_adapter::OAuth2Adapter)
            }
            IdentityProviderKind::Wechat => Box::new(wechat_adapter::WechatAdapter),
            _ => unreachable!("unsupported provider kind for social login"),
        }
    }

    pub async fn find_provider_by_code(
        &self,
        provider_code: &str,
    ) -> Result<ip::Model, SocialLoginError> {
        ip::Entity::find()
            .filter(ip::Column::Code.eq(provider_code))
            .filter(ip::Column::Kind.is_in([
                IdentityProviderKind::Oauth2,
                IdentityProviderKind::Oidc,
                IdentityProviderKind::Wechat,
            ]))
            .filter(ip::Column::Enabled.eq(true))
            .one(self.db)
            .await
            .map_err(|e| SocialLoginError::Internal(e.to_string()))?
            .ok_or(SocialLoginError::ProviderNotFound)
    }

    pub async fn prepare_login_state(
        &self,
        provider: &ip::Model,
        provider_code: &str,
        auth_request_id: Option<Uuid>,
        redirect: &str,
    ) -> Result<PreparedLoginState, SocialLoginError> {
        crate::service::provider::validate_configuration(
            provider,
            provider.client_secret_enc.is_some(),
        )
        .map_err(|_| SocialLoginError::ProviderMisconfigured)?;
        let state_token = pero_utils::crypto::generate_token();
        let state_hash = pero_utils::crypto::sha256_hex(&state_token);

        let needs_pkce = matches!(
            provider.kind,
            IdentityProviderKind::Oauth2 | IdentityProviderKind::Oidc
        );
        let pkce = if needs_pkce {
            Some(pero_utils::oauth::pkce::PkcePair::generate())
        } else {
            None
        };

        let nonce =
            (provider.kind == IdentityProviderKind::Oidc).then(pero_utils::crypto::generate_nonce);
        let mut force_login = false;
        let mut reauthenticate_after = None;
        if let Some(id) = auth_request_id {
            let request = crate::db::entity::authorization_requests::Entity::find_by_id(id)
                .one(self.db)
                .await
                .map_err(|e| SocialLoginError::Internal(e.to_string()))?
                .ok_or(SocialLoginError::InvalidState)?;
            force_login = crate::service::oauth::has_prompt(request.prompt.as_deref(), "login")
                || request.max_age.is_some();
            if force_login {
                reauthenticate_after = Some(request.created_at.unix_timestamp());
            }
            if force_login && provider.kind != IdentityProviderKind::Oidc {
                return Err(SocialLoginError::ProviderMisconfigured);
            }
        }
        let social_value = crate::cache::key::SocialStateValue {
            redirect: pero_utils::redirect::safe_site_redirect(redirect, "/account/profile"),
            auth_request_id: auth_request_id.map(|id| id.to_string()),
            provider_id: provider.id.to_string(),
            nonce: nonce.clone(),
            code_verifier: pkce.as_ref().map(|p| p.code_verifier.clone()),
            reauthenticate_after,
        };

        if let Ok(key) = social_state.key_with_ttl(
            Duration::from_secs(self.oauth2_config.auth_code_ttl_seconds),
            &state_hash,
        ) {
            self.cache
                .set(key, &social_value)
                .await
                .map_err(|e| SocialLoginError::Internal(e.to_string()))?;
        }

        let auth_endpoint = provider.authorization_endpoint.as_deref().unwrap_or("");
        if auth_endpoint.is_empty()
            || pero_utils::redirect::validate_provider_endpoint_uri(auth_endpoint).is_err()
        {
            return Err(SocialLoginError::ProviderMisconfigured);
        }

        let client_id = provider.client_id.as_deref().unwrap_or("");
        let redirect_uri = helper::social_callback_url(&self.sso_config.base_url, provider_code);
        let provider_scopes = provider.scopes.join(" ");

        let adapter = Self::adapter_for(&provider.kind);
        let mut authorize_url = adapter.build_authorize_url(&adapter::AuthorizeParams {
            endpoint: auth_endpoint.to_owned(),
            client_id: client_id.to_owned(),
            redirect_uri,
            scope: provider_scopes,
            state: state_token.clone(),
            code_challenge: pkce.map(|p| p.code_challenge),
        });

        if let Some(nonce) = nonce {
            pero_utils::encode::append_query_param(&mut authorize_url, "nonce", &nonce);
        }
        if force_login {
            pero_utils::encode::append_query_param(&mut authorize_url, "prompt", "login");
            pero_utils::encode::append_query_param(&mut authorize_url, "max_age", "0");
        }

        Ok(PreparedLoginState {
            state_token,
            state_hash,
            authorize_url,
        })
    }

    pub async fn validate_callback_state(
        &self,
        state_hash: &str,
        provider_code: &str,
    ) -> Result<ValidatedCallbackState, SocialLoginError> {
        let social_value = match social_state.key(state_hash) {
            Ok(key) => self
                .cache
                .take::<crate::cache::key::SocialStateValue>(key)
                .await
                .map_err(|e| SocialLoginError::Internal(e.to_string()))?,
            Err(_) => return Err(SocialLoginError::InvalidState),
        };
        let social_value = social_value.ok_or(SocialLoginError::InvalidState)?;

        let auth_request_id = match social_value.auth_request_id {
            Some(ref raw) => {
                Some(Uuid::parse_str(raw).map_err(|_| SocialLoginError::InvalidState)?)
            }
            None => None,
        };
        let provider_id = Uuid::parse_str(&social_value.provider_id)
            .map_err(|_| SocialLoginError::InvalidState)?;

        let provider = find_provider_with_secret(self.db, provider_id)
            .await
            .map_err(|e| SocialLoginError::Internal(e.to_string()))?;
        let provider = match provider {
            Some(p) if p.provider.code == provider_code && p.provider.enabled => p,
            _ => return Err(SocialLoginError::InvalidState),
        };

        Ok(ValidatedCallbackState {
            social_value,
            provider,
            auth_request_id,
        })
    }

    pub async fn exchange_code(
        &self,
        provider: &ProviderWithSecret,
        code: &str,
        code_verifier: &Option<String>,
    ) -> Result<TokenResult, SocialLoginError> {
        let endpoint = provider
            .provider
            .token_endpoint
            .as_deref()
            .ok_or_else(|| SocialLoginError::TokenExchangeFailed("no token_endpoint".into()))?;
        pero_utils::redirect::validate_provider_endpoint_uri(endpoint)
            .map_err(|_| SocialLoginError::TokenExchangeFailed("invalid token_endpoint".into()))?;
        let client_id = provider.provider.client_id.as_deref().unwrap_or("");
        let secret = provider.client_secret.as_deref().unwrap_or("");
        let redirect =
            helper::social_callback_url(&self.sso_config.base_url, &provider.provider.code);

        let adapter = Self::adapter_for(&provider.provider.kind);
        adapter
            .exchange_code(ExchangeCodeParams {
                http_client: self.http_client,
                token_endpoint: endpoint,
                client_id,
                client_secret: secret,
                code,
                redirect_uri: &redirect,
                code_verifier: code_verifier.as_deref(),
            })
            .await
            .map_err(SocialLoginError::TokenExchangeFailed)
    }

    pub async fn fetch_userinfo(
        &self,
        provider: &ProviderWithSecret,
        token_result: &TokenResult,
        nonce: Option<&str>,
        reauthenticate_after: Option<i64>,
    ) -> Result<SocialUserInfo, SocialLoginError> {
        let oidc_claims = if provider.provider.kind == IdentityProviderKind::Oidc {
            Some(
                self.validate_oidc_token(
                    &provider.provider,
                    token_result,
                    nonce,
                    reauthenticate_after,
                )
                .await?,
            )
        } else {
            None
        };
        let endpoint = provider
            .provider
            .userinfo_endpoint
            .as_deref()
            .ok_or_else(|| SocialLoginError::UserinfoFailed("no userinfo_endpoint".into()))?;
        pero_utils::redirect::validate_provider_endpoint_uri(endpoint)
            .map_err(|_| SocialLoginError::UserinfoFailed("invalid userinfo_endpoint".into()))?;

        let adapter = Self::adapter_for(&provider.provider.kind);
        let adapter_info = adapter
            .fetch_userinfo(self.http_client, endpoint, token_result)
            .await
            .map_err(SocialLoginError::UserinfoFailed)?;

        let authenticated_at = oidc_claims
            .as_ref()
            .and_then(|claims| claims.get("auth_time")?.as_i64())
            .and_then(|value| time::OffsetDateTime::from_unix_timestamp(value).ok());
        if let Some(claims) = oidc_claims
            && claims.get("sub").and_then(serde_json::Value::as_str)
                != Some(adapter_info.sub.as_str())
        {
            return Err(SocialLoginError::UserinfoFailed(
                "upstream subject mismatch".into(),
            ));
        }
        if adapter_info.sub.is_empty() {
            return Err(SocialLoginError::UserinfoFailed("missing subject".into()));
        }
        let mut email = adapter_info.email;
        let mut email_verified = adapter_info.email_verified;

        if email.is_none()
            && matches!(
                provider.provider.kind,
                IdentityProviderKind::Oauth2 | IdentityProviderKind::Oidc
            )
            && let Some((e, v)) = self
                .fetch_provider_emails(provider, &token_result.access_token)
                .await?
        {
            email = Some(e);
            email_verified = v;
        }

        Ok(SocialUserInfo {
            authenticated_at,
            sub: adapter_info.sub,
            email,
            email_verified,
            name: adapter_info.name,
            avatar_url: adapter_info.avatar_url,
            profile_extra: adapter_info.profile_extra,
        })
    }

    async fn fetch_provider_emails(
        &self,
        provider: &ProviderWithSecret,
        access_token: &str,
    ) -> Result<Option<(String, bool)>, SocialLoginError> {
        let endpoint = match provider
            .provider
            .settings
            .get("emails_endpoint")
            .and_then(|v| v.as_str())
        {
            Some(e) => e,
            None => return Ok(None),
        };
        pero_utils::redirect::validate_provider_endpoint_uri(endpoint)
            .map_err(|_| SocialLoginError::UserinfoFailed("invalid emails_endpoint".into()))?;
        let resp = self
            .http_client
            .get(endpoint)
            .header(
                http::header::USER_AGENT,
                http::HeaderValue::from_static("Pero/1.0"),
            )
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|e| SocialLoginError::UserinfoFailed(format!("emails fetch: {e}")))?
            .error_for_status()
            .map_err(|e| SocialLoginError::UserinfoFailed(format!("emails fetch: {e}")))?;
        let emails: serde_json::Value = resp
            .json()
            .map_err(|e| SocialLoginError::UserinfoFailed(format!("emails parse: {e}")))?;
        let Some(list) = emails.as_array() else {
            return Ok(None);
        };
        for entry in list {
            let is_primary = entry
                .get("primary")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let is_verified = entry
                .get("verified")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            if is_primary && let Some(addr) = helper::str_field(entry, "email") {
                return Ok(Some((addr, is_verified)));
            }
        }
        for entry in list {
            let is_verified = entry
                .get("verified")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            if is_verified && let Some(addr) = helper::str_field(entry, "email") {
                return Ok(Some((addr, true)));
            }
        }
        Ok(None)
    }

    pub async fn resolve_identity(
        &self,
        provider: &ProviderWithSecret,
        info: &SocialUserInfo,
        auth_request_id: Option<Uuid>,
        redirect: &str,
    ) -> Result<IdentityResolution, SocialLoginError> {
        let existing = identities::Entity::find()
            .filter(identities::Column::ProviderId.eq(provider.provider.id))
            .filter(identities::Column::Subject.eq(&info.sub))
            .filter(identities::Column::UnboundAt.is_null())
            .one(self.db)
            .await
            .map_err(|e| SocialLoginError::Internal(e.to_string()))?;

        if let Some(identity) = existing {
            let user = users::Entity::find_by_id(identity.user_id)
                .one(self.db)
                .await
                .map_err(|e| SocialLoginError::Internal(e.to_string()))?
                .ok_or_else(|| SocialLoginError::Internal("user not found".into()))?;
            if user.deleted_at.is_some() || user.status != UserStatus::Active {
                return Err(SocialLoginError::Internal("user unavailable".into()));
            }
            let id = identity.id;
            let now = time::OffsetDateTime::now_utc();
            let mut a: identities::ActiveModel = identity.into();
            a.profile = Set(info.profile());
            a.last_login_at = Set(Some(now));
            a.update(self.db)
                .await
                .map_err(|e| SocialLoginError::Internal(e.to_string()))?;
            return Ok(IdentityResolution::Resolved {
                user,
                identity_id: id,
            });
        }

        if info.sub.is_empty() {
            return Err(SocialLoginError::Internal("no subject".into()));
        }

        if let Some(user) = self.find_social_link_user(info).await? {
            let nonce = self
                .create_social_link(provider, info, &user, auth_request_id, redirect)
                .await?;
            return Ok(IdentityResolution::NeedsAccountLink { nonce });
        }

        Ok(IdentityResolution::NeedsRegistration {
            info: SocialUserInfo {
                authenticated_at: info.authenticated_at,
                sub: info.sub.clone(),
                email: info.email.clone(),
                email_verified: info.email_verified,
                name: info.name.clone(),
                avatar_url: info.avatar_url.clone(),
                profile_extra: info.profile_extra.clone(),
            },
            auth_request_id,
        })
    }

    pub async fn find_social_link_user(
        &self,
        info: &SocialUserInfo,
    ) -> Result<Option<users::Model>, SocialLoginError> {
        if !info.email_verified {
            return Ok(None);
        }

        let Some(email) = info
            .email
            .as_deref()
            .map(str::trim)
            .filter(|v| !v.is_empty())
        else {
            return Ok(None);
        };

        let user = users::Entity::find()
            .filter(users::Column::Email.eq(email))
            .filter(users::Column::DeletedAt.is_null())
            .one(self.db)
            .await
            .map_err(|e| SocialLoginError::Internal(e.to_string()))?;

        match user {
            Some(u) if u.status == UserStatus::Active => Ok(Some(u)),
            Some(_) => Err(SocialLoginError::Internal("user unavailable".into())),
            None => Ok(None),
        }
    }
}
