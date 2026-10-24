//! Credential changes share the user lock and commit with their session and audit effects.
use super::{ManagementError, security as sec};
use crate::{db::entity::sso_sessions, state::app::AppState};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QuerySelect, TransactionTrait};

pub async fn ensure_oidc_reauthentication_allowed<C: sea_orm::ConnectionTrait>(
    db: &C,
    session: &sso_sessions::Model,
) -> Result<(), ManagementError> {
    if session.recovery_pending
        || session.mfa_required
            && session.mfa_verified_at.is_none()
            && sec::mfa_enabled(db, session.user_id).await?
    {
        return Err(ManagementError::Invalid("unauthorized"));
    }
    Ok(())
}

/// Record only an already validated upstream OIDC proof for the bound identity.
/// An unenrolled administrator remains restricted until TOTP enrollment completes.
pub async fn record_oidc_reauthentication(
    state: &AppState,
    session: &sso_sessions::Model,
    provider_id: uuid::Uuid,
    subject: &str,
    authenticated_at: Option<time::OffsetDateTime>,
) -> Result<(), ManagementError> {
    use crate::db::{
        entity::identities,
        enums::{IdentityKind, UserStatus},
    };
    let txn = state.db.begin().await?;
    let user = super::password::PasswordIdentityService::lock_user(&txn, session.user_id).await?;
    if user.status != UserStatus::Active {
        return Err(ManagementError::Invalid("unauthorized"));
    }
    let current = crate::db::helper::session::valid_query(
        time::OffsetDateTime::now_utc(),
        state.config.sso.session_idle_ttl_seconds,
    )
    .filter(sso_sessions::Column::Id.eq(session.id))
    .filter(sso_sessions::Column::UserId.eq(session.user_id))
    .lock_exclusive()
    .one(&txn)
    .await?
    .ok_or(ManagementError::Invalid("unauthorized"))?;
    ensure_oidc_reauthentication_allowed(&txn, &current).await?;
    let authenticated_at = authenticated_at
        .filter(|at| {
            *at > time::OffsetDateTime::now_utc() - time::Duration::seconds(sec::RECENT_SECONDS)
        })
        .ok_or(ManagementError::Invalid("reauth_required"))?;
    super::provider::require_enabled_social(&txn, provider_id).await?;
    let bound = identities::Entity::find()
        .filter(identities::Column::UserId.eq(user.id))
        .filter(identities::Column::ProviderId.eq(provider_id))
        .filter(identities::Column::Kind.eq(IdentityKind::Oauth))
        .filter(identities::Column::Subject.eq(subject))
        .filter(identities::Column::UnboundAt.is_null())
        .one(&txn)
        .await?;
    if bound.is_none() {
        return Err(ManagementError::Invalid("invalid_credentials"));
    }
    sec::execute(
        &txn,
        "UPDATE sso_sessions SET oidc_reauthenticated_at=$2 WHERE id=$1",
        vec![current.id.into(), authenticated_at.into()],
    )
    .await?;
    txn.commit().await?;
    Ok(())
}
pub struct Change {
    pub codes: Option<Vec<String>>,
    pub session_id: uuid::Uuid,
    pub token: Option<String>,
}
pub async fn change(
    state: &AppState,
    s: &sso_sessions::Model,
    action: &str,
    code: &str,
    password: &str,
) -> Result<Change, ManagementError> {
    use pero_cache_redis::{RateLimitError, enforce_rate_limit};
    let key = crate::cache::key::mfa_attempt.key(&s.user_id.to_string())?;
    enforce_rate_limit(&state.cache, &key, 10)
        .await
        .map_err(|e| match e {
            RateLimitError::Denied { .. } => ManagementError::Invalid("rate_limited"),
            RateLimitError::Redis(e) => ManagementError::Credential(e),
        })?;
    let txn = state.db.begin().await?;
    let user =
        crate::service::password::PasswordIdentityService::lock_user(&txn, s.user_id).await?;
    if user.status != crate::db::enums::UserStatus::Active {
        return Err(ManagementError::Invalid("unauthorized"));
    }
    // Serialize factor changes and challenge completion with credential revocation.
    let current = crate::db::helper::session::valid_query(
        time::OffsetDateTime::now_utc(),
        state.config.sso.session_idle_ttl_seconds,
    )
    .filter(sso_sessions::Column::Id.eq(s.id))
    .lock_exclusive()
    .one(&txn)
    .await?
    .ok_or(ManagementError::Invalid("unauthorized"))?;
    let f = sec::factor(&txn, s.user_id).await?;
    let enabled = f.as_ref().is_some_and(|f| f.enabled);
    let pending = current.mfa_required && current.mfa_verified_at.is_none();
    let mut codes = None;
    match action {
        "verify" => {
            if !pending
                || current.created_at < time::OffsetDateTime::now_utc() - time::Duration::minutes(5)
            {
                return Err(ManagementError::Invalid("unauthorized"));
            }
            sec::verify(&txn, s.user_id, f.as_ref(), code, false).await?;
            sec::execute(
                &txn,
                "UPDATE sso_sessions SET mfa_verified_at=now() WHERE id=$1",
                vec![s.id.into()],
            )
            .await?;
        }
        "recover" => {
            if !pending
                || current.created_at < time::OffsetDateTime::now_utc() - time::Duration::minutes(5)
            {
                return Err(ManagementError::Invalid("unauthorized"));
            }
            sec::verify(&txn, s.user_id, f.as_ref(), code, true).await?;
            crate::service::account_security::revoke_sessions(
                &txn,
                s.user_id,
                sea_orm::Condition::all().add(sso_sessions::Column::Id.ne(s.id)),
                "mfa_recovery",
            )
            .await?;
            sec::execute(
                &txn,
                "UPDATE sso_sessions SET recovery_pending=true WHERE id=$1",
                vec![s.id.into()],
            )
            .await?;
            sec::notify(&txn, &user, "mfa_recovery").await?;
            codes = Some(vec![]);
        }
        "reauth" => {
            if pending || current.recovery_pending {
                return Err(ManagementError::Invalid("unauthorized"));
            }
            if enabled {
                sec::verify(&txn, s.user_id, f.as_ref(), code, false).await?;
            }
            let identity = super::password::PasswordIdentityService::find(&txn, s.user_id).await?;
            let authenticated_at = if let Some(identity) = identity {
                if !crate::service::password::PasswordIdentityService::verify_password_hash(
                    password,
                    identity.password_hash.as_deref(),
                )
                .await?
                {
                    return Err(ManagementError::Invalid("invalid_credentials"));
                }
                time::OffsetDateTime::now_utc()
            } else {
                current
                    .oidc_reauthenticated_at
                    .filter(|at| {
                        *at > time::OffsetDateTime::now_utc()
                            - time::Duration::seconds(sec::RECENT_SECONDS)
                    })
                    .ok_or(ManagementError::Invalid("reauth_required"))?
            };
            sec::execute(&txn,"UPDATE sso_sessions SET authenticated_at=$2,reauthenticated_at=$2,oidc_reauthenticated_at=NULL,mfa_verified_at=CASE WHEN mfa_required THEN now() ELSE mfa_verified_at END WHERE id=$1",vec![s.id.into(), authenticated_at.into()]).await?;
        }
        "setup" => {
            let recent = sec::recent(&txn, s.id, state.config.sso.session_idle_ttl_seconds).await?;
            let fresh_primary = !enabled
                && current
                    .oidc_reauthenticated_at
                    .or(current.reauthenticated_at)
                    .is_some_and(|at| {
                        at > time::OffsetDateTime::now_utc()
                            - time::Duration::seconds(sec::RECENT_SECONDS)
                    });
            if !current.recovery_pending && ((pending && enabled) || !(recent || fresh_primary)) {
                return Err(ManagementError::Invalid("reauth_required"));
            }
            if enabled && !current.recovery_pending {
                return Err(ManagementError::Invalid("mfa_already_enabled"));
            }
            let secret = totp_rs::Secret::generate().to_base32();
            sec::execute(&txn,"INSERT INTO user_mfa(user_id,secret_enc,pending_secret_enc,setup_session) VALUES($1,pgp_sym_encrypt($2,current_setting('app.encrypt_key')),pgp_sym_encrypt($2,current_setting('app.encrypt_key')),$3) ON CONFLICT(user_id) DO UPDATE SET pending_secret_enc=EXCLUDED.pending_secret_enc,setup_session=EXCLUDED.setup_session,setup_expires_at=now()+interval '5 minutes'",vec![s.user_id.into(),secret.into(),s.id.into()]).await?;
            codes = Some(vec![]);
        }
        "enable" => {
            let mut f = f
                .filter(|f| {
                    f.pending_secret.is_some()
                        && f.setup_session == Some(s.id)
                        && f.setup_expires_at > time::OffsetDateTime::now_utc()
                })
                .ok_or(ManagementError::Invalid("invalid_request"))?;
            f.secret = f
                .pending_secret
                .take()
                .ok_or(ManagementError::Invalid("invalid_request"))?;
            f.last_step = -1;
            let step = sec::verified_step(&f, code)?;
            sec::execute(&txn,"UPDATE user_mfa SET secret_enc=pending_secret_enc,pending_secret_enc=NULL,setup_session=NULL,enabled=true,last_step=$2 WHERE user_id=$1",vec![s.user_id.into(),step.into()]).await?;
            let generated = sec::codes(&txn, s.user_id).await?;
            crate::service::account_security::revoke_sessions(
                &txn,
                s.user_id,
                sea_orm::Condition::all().add(sso_sessions::Column::Id.ne(s.id)),
                "mfa_enabled",
            )
            .await?;
            sec::execute(&txn,"UPDATE sso_sessions SET mfa_required=true,mfa_verified_at=now(),reauthenticated_at=COALESCE(oidc_reauthenticated_at,reauthenticated_at),authenticated_at=COALESCE(oidc_reauthenticated_at,authenticated_at),recovery_pending=false WHERE id=$1",vec![s.id.into()]).await?;
            sec::notify(&txn, &user, "mfa_enabled").await?;
            codes = Some(generated);
        }
        "disable" | "codes" => {
            if !sec::recent(&txn, s.id, state.config.sso.session_idle_ttl_seconds).await? {
                return Err(ManagementError::Invalid("reauth_required"));
            }
            // Require a fresh OTP for factor changes, even within the recent-auth window.
            sec::verify(&txn, s.user_id, f.as_ref(), code, false).await?;
            if action == "disable" {
                if sec::role(&txn, s.user_id).await?.is_some() {
                    return Err(ManagementError::Invalid("mfa_required"));
                }
                sec::execute(
                    &txn,
                    "DELETE FROM user_mfa WHERE user_id=$1",
                    vec![s.user_id.into()],
                )
                .await?;
                crate::service::session::SessionService::revoke_all_login_state_for_user_in_db(
                    &txn,
                    s.user_id,
                    "mfa_disabled",
                )
                .await?;
            } else {
                codes = Some(sec::codes(&txn, s.user_id).await?);
            }
            sec::notify(&txn, &user, "mfa_changed").await?;
        }
        _ => return Err(ManagementError::Invalid("invalid_request")),
    }
    sec::execute(&txn,"INSERT INTO audit_events(actor_id,actor_username,action,target,outcome,http_status) VALUES($1,$2,$3,'/account/security','success',200)",vec![user.id.into(),user.username.into(),format!("security:{}",action).into()]).await?;
    let mut session_id = s.id;
    let mut token = None;
    if matches!(action, "verify" | "enable" | "reauth" | "recover") {
        let raw = pero_utils::crypto::generate_token();
        let new_id =
            crate::db::helper::session::rotate(&txn, s.id, pero_utils::crypto::sha256_hex(&raw))
                .await?;
        crate::service::account_security::revoke_sessions(
            &txn,
            s.user_id,
            sea_orm::Condition::all().add(sso_sessions::Column::Id.eq(s.id)),
            "security_rotation",
        )
        .await?;
        session_id = new_id;
        token = Some(raw);
    }
    txn.commit().await?;
    Ok(Change {
        codes,
        session_id,
        token,
    })
}
