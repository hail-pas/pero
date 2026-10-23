//! Register an upstream identity, access and pending verification in one transaction.
use sea_orm::{ActiveModelTrait, EntityTrait, Set, TransactionTrait};
use uuid::Uuid;

use super::{SocialLoginService, SocialUserInfo};
use crate::db::enums::{IdentityKind, UserStatus};

impl SocialLoginService<'_> {
    pub async fn register_user(
        &self,
        provider: &crate::db::helper::provider::ProviderWithSecret,
        info: SocialUserInfo,
        auth_request_id: Option<Uuid>,
    ) -> Result<(crate::db::entity::users::Model, Uuid), String> {
        use crate::db::entity::contact_change_requests as ccr;
        use crate::db::entity::{identities, users};
        use crate::db::enums::{ContactChangeStatus, ContactChangeType};

        let txn = self.db.begin().await.map_err(|e| format!("{e}"))?;
        crate::service::provider::require_enabled_social(&txn, provider.provider.id)
            .await
            .map_err(|error| error.to_string())?;
        let now = time::OffsetDateTime::now_utc();
        let user_id = Uuid::now_v7();
        let username = format!("u_{}", user_id.simple());

        let user = users::ActiveModel {
            id: Set(user_id),
            username: Set(username),
            email: Set(if info.email_verified {
                info.email.clone()
            } else {
                None
            }),
            email_verified_at: Set(if info.email_verified { Some(now) } else { None }),
            phone: Set(None),
            phone_verified_at: Set(None),
            nickname: Set(info.name.clone()),
            avatar_url: Set(info.avatar_url.clone()),
            status: Set(UserStatus::Active),
            created_at: Set(now),
            updated_at: Set(now),
            deleted_at: Set(None),
        }
        .insert(&txn)
        .await
        .map_err(|e| format!("{e}"))?;

        let identity_id = Uuid::now_v7();
        identities::ActiveModel {
            id: Set(identity_id),
            user_id: Set(user_id),
            provider_id: Set(provider.provider.id),
            kind: Set(IdentityKind::Oauth),
            subject: Set(info.sub.clone()),
            password_hash: Set(None),
            password_algorithm: Set(None),
            password_updated_at: Set(None),
            profile: Set(info.profile()),
            last_login_at: Set(Some(now)),
            created_at: Set(now),
            updated_at: Set(now),
            unbound_at: Set(None),
        }
        .insert(&txn)
        .await
        .map_err(|e| format!("{e}"))?;

        crate::service::access::insert_auto_access(&txn, user_id, auth_request_id, now)
            .await
            .map_err(|e| format!("auto app access: {e}"))?;

        let pending_email_data = if !info.email_verified && !self.notification.endpoint.is_empty() {
            if let Some(ref email) = info.email {
                use crate::service::contact::{
                    ContactChannel, expire_reservations, is_contact_taken,
                };
                expire_reservations(&txn, ContactChannel::Email, email, user_id)
                    .await
                    .map_err(|e| format!("contact reservation expiry: {e}"))?;
                if !is_contact_taken(&txn, ContactChannel::Email, email, user_id)
                    .await
                    .map_err(|e| format!("contact availability query: {e}"))?
                {
                    let verification = crate::service::verification::generate_code();
                    let inserted = ccr::Entity::insert(ccr::ActiveModel {
                        id: Set(Uuid::now_v7()),
                        user_id: Set(user_id),
                        change_type: Set(ContactChangeType::Email),
                        new_value: Set(email.clone()),
                        status: Set(ContactChangeStatus::Pending),
                        verification_code_hash: Set(verification.code_hash.clone()),
                        nonce: Set(verification.nonce.clone()),
                        requested_at: Set(now),
                        expires_at: Set(crate::service::verification::expires_in(
                            time::Duration::minutes(15),
                        )),
                        verified_at: Set(None),
                        cancelled_at: Set(None),
                        created_at: Set(now),
                        updated_at: Set(now),
                    })
                    // A concurrent reservation is optional; handle it in SQL so PostgreSQL
                    // keeps the registration transaction usable after a unique conflict.
                    .on_conflict(sea_orm::sea_query::OnConflict::new().do_nothing().to_owned())
                    .exec_without_returning(&txn)
                    .await
                    .map_err(|e| format!("pending contact reservation: {e}"))?;
                    (inserted > 0).then(|| (email.clone(), verification.code, verification.nonce))
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };

        if let Some((email, code, nonce)) = pending_email_data {
            crate::service::notify::enqueue_verification(
                &txn,
                user_id,
                &self.sso_config.base_url,
                "email",
                &email,
                &code,
                &nonce,
            )
            .await
            .map_err(|_| "notification_queue_failed".to_owned())?;
        }
        txn.commit().await.map_err(|e| format!("{e}"))?;

        Ok((user, identity_id))
    }
}
