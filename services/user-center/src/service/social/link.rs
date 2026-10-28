//! Account-link state and identity writes for an authenticated local account.
use super::{SocialLinkError, SocialLoginError, SocialLoginService, SocialUserInfo};
use crate::{
    cache::key::social_link,
    db::{
        entity::{identities, users},
        enums::{IdentityKind, UserStatus},
        helper::provider::ProviderWithSecret,
    },
};
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set, TransactionTrait};
use std::time::Duration;
use uuid::Uuid;

enum LinkProof<'a> {
    Password(&'a identities::Model),
    Session(&'a crate::state::session::SsoSession),
}

impl SocialLoginService<'_> {
    pub async fn create_social_link(
        &self,
        provider: &ProviderWithSecret,
        info: &SocialUserInfo,
        user: &users::Model,
        auth_request_id: Option<Uuid>,
        redirect: &str,
    ) -> Result<String, SocialLoginError> {
        let nonce = pero_utils::crypto::generate_token();
        let value = crate::cache::key::SocialLinkValue {
            redirect: redirect.to_owned(),
            auth_request_id: auth_request_id.map(|id| id.to_string()),
            user_id: user.id.to_string(),
            provider_id: provider.provider.id.to_string(),
            provider_code: provider.provider.code.clone(),
            provider_name: provider.provider.name.clone(),
            subject: info.sub.clone(),
            email: info.email.clone(),
            email_verified: info.email_verified,
            name: info.name.clone().or_else(|| user.nickname.clone()),
            avatar_url: info.avatar_url.clone(),
        };
        let key = social_link
            .key_with_ttl(
                Duration::from_secs(self.oauth2_config.auth_code_ttl_seconds),
                &nonce,
            )
            .map_err(|e| SocialLoginError::Internal(e.to_string()))?;
        self.cache
            .set(key, &value)
            .await
            .map_err(|e| SocialLoginError::Internal(e.to_string()))?;
        Ok(nonce)
    }

    pub async fn load_social_link(
        &self,
        nonce: &str,
    ) -> Result<Option<crate::cache::key::SocialLinkValue>, SocialLoginError> {
        let key = social_link
            .key(nonce)
            .map_err(|e| SocialLoginError::Internal(e.to_string()))?;
        self.cache
            .get::<crate::cache::key::SocialLinkValue>(key)
            .await
            .map_err(|e| SocialLoginError::Internal(e.to_string()))
    }

    pub async fn link_social_identity(
        &self,
        verified: &identities::Model,
        provider_id: Uuid,
        link: &crate::cache::key::SocialLinkValue,
    ) -> Result<Uuid, SocialLinkError> {
        let profile = serde_json::json!({
            "email": link.email,
            "email_verified": link.email_verified,
            "name": link.name,
            "picture": link.avatar_url,
        });
        self.store_social_identity(
            LinkProof::Password(verified),
            provider_id,
            &link.subject,
            profile,
        )
        .await
    }

    pub async fn bind_social_identity(
        &self,
        session: &crate::state::session::SsoSession,
        provider_id: Uuid,
        info: &SocialUserInfo,
    ) -> Result<Uuid, SocialLinkError> {
        self.store_social_identity(
            LinkProof::Session(session),
            provider_id,
            &info.sub,
            info.profile(),
        )
        .await
    }

    async fn store_social_identity(
        &self,
        proof: LinkProof<'_>,
        provider_id: Uuid,
        subject: &str,
        profile: serde_json::Value,
    ) -> Result<Uuid, SocialLinkError> {
        let user_id = match &proof {
            LinkProof::Password(identity) => identity.user_id,
            LinkProof::Session(session) => session.user_id,
        };
        let txn = self
            .db
            .begin()
            .await
            .map_err(|e| SocialLinkError::Internal(e.to_string()))?;
        let user = crate::service::password::PasswordIdentityService::lock_user(&txn, user_id)
            .await
            .map_err(|e| SocialLinkError::Internal(e.to_string()))?;
        if user.status != UserStatus::Active {
            return Err(SocialLinkError::InvalidSession);
        }
        crate::service::provider::require_enabled_social(&txn, provider_id)
            .await
            .map_err(|error| SocialLinkError::Internal(error.to_string()))?;
        match proof {
            LinkProof::Password(verified) => {
                if crate::service::security::mfa_enabled(&txn, user_id)
                    .await
                    .map_err(|e| SocialLinkError::Internal(e.to_string()))?
                    || crate::service::security::role(&txn, user_id)
                        .await
                        .map_err(|e| SocialLinkError::Internal(e.to_string()))?
                        .is_some()
                {
                    return Err(SocialLinkError::ReauthenticationRequired);
                }
                crate::service::password::PasswordIdentityService::ensure_unchanged(&txn, verified)
                    .await
                    .map_err(|e| SocialLinkError::Internal(e.to_string()))?;
            }
            LinkProof::Session(session) => {
                if crate::db::helper::session::lock_active(
                    &txn,
                    session.id,
                    user_id,
                    self.sso_config.session_idle_ttl_seconds,
                )
                .await
                .map_err(|e| SocialLinkError::Internal(e.to_string()))?
                .is_none()
                {
                    return Err(SocialLinkError::InvalidSession);
                }
                if !crate::service::security::recent(
                    &txn,
                    session.id,
                    self.sso_config.session_idle_ttl_seconds,
                )
                .await
                .map_err(|e| SocialLinkError::Internal(e.to_string()))?
                {
                    return Err(SocialLinkError::ReauthenticationRequired);
                }
            }
        }
        let now = time::OffsetDateTime::now_utc();

        let by_subject = identities::Entity::find()
            .filter(identities::Column::ProviderId.eq(provider_id))
            .filter(identities::Column::Subject.eq(subject))
            .filter(identities::Column::UnboundAt.is_null())
            .one(&txn)
            .await
            .map_err(|e| SocialLinkError::Internal(e.to_string()))?;

        if let Some(identity) = by_subject {
            if identity.user_id != user_id {
                return Err(SocialLinkError::IdentityTaken);
            }
            let id = identity.id;
            let mut active: identities::ActiveModel = identity.into();
            active.profile = Set(profile);
            active.last_login_at = Set(Some(now));
            active.updated_at = Set(now);
            active
                .update(&txn)
                .await
                .map_err(|e| SocialLinkError::Internal(e.to_string()))?;
            txn.commit()
                .await
                .map_err(|e| SocialLinkError::Internal(e.to_string()))?;
            return Ok(id);
        }

        let existing_provider = identities::Entity::find()
            .filter(identities::Column::UserId.eq(user_id))
            .filter(identities::Column::ProviderId.eq(provider_id))
            .filter(identities::Column::Kind.eq(IdentityKind::Oauth))
            .filter(identities::Column::UnboundAt.is_null())
            .one(&txn)
            .await
            .map_err(|e| SocialLinkError::Internal(e.to_string()))?;
        if existing_provider.is_some() {
            return Err(SocialLinkError::ProviderAlreadyLinked);
        }

        let identity_id = Uuid::now_v7();
        identities::ActiveModel {
            id: Set(identity_id),
            user_id: Set(user_id),
            provider_id: Set(provider_id),
            kind: Set(IdentityKind::Oauth),
            subject: Set(subject.to_owned()),
            password_hash: Set(None),
            password_algorithm: Set(None),
            password_updated_at: Set(None),
            profile: Set(profile),
            last_login_at: Set(Some(now)),
            created_at: Set(now),
            updated_at: Set(now),
            unbound_at: Set(None),
        }
        .insert(&txn)
        .await
        .map_err(|e| {
            if crate::db::error::is_unique_violation(&e) {
                SocialLinkError::ProviderAlreadyLinked
            } else {
                SocialLinkError::Internal(e.to_string())
            }
        })?;

        crate::service::security::notify(&txn, &user, "identity_linked")
            .await
            .map_err(|e| SocialLinkError::Internal(e.to_string()))?;
        txn.commit()
            .await
            .map_err(|e| SocialLinkError::Internal(e.to_string()))?;
        Ok(identity_id)
    }

    pub async fn delete_social_link_cache(&self, nonce: &str) {
        if let Ok(key) = social_link.key(nonce) {
            let _ = self.cache.del(key).await;
        }
    }
}
