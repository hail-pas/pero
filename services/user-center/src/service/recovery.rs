//! Recovery credentials and their pending notifications share the user's lock.
use sea_orm::{
    ColumnTrait, ConnectionTrait, DbBackend, DbErr, EntityTrait, QueryFilter, Statement,
    sea_query::Expr,
};
use uuid::Uuid;

/// Call inside a transaction after locking the user. This also covers tokens
/// issued before notification ownership metadata was introduced.
pub async fn invalidate<C: ConnectionTrait>(db: &C, user_id: Uuid) -> Result<(), DbErr> {
    use crate::db::entity::password_reset_tokens as prt;
    prt::Entity::update_many()
        .col_expr(
            prt::Column::ConsumedAt,
            Expr::value(Some(time::OffsetDateTime::now_utc())),
        )
        .filter(prt::Column::UserId.eq(user_id))
        .filter(prt::Column::ConsumedAt.is_null())
        .exec(db)
        .await?;
    db.execute_raw(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "DELETE FROM notification_outbox WHERE user_id = $1 AND kind = 'reset_password'",
        [user_id.into()],
    ))
    .await?;
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum RecoveryError {
    #[error("Recovery dependency unavailable")]
    Dependency(#[from] DbErr),
    #[error("Could not sign recovery token")]
    Signing(#[from] jsonwebtoken::errors::Error),
    #[error("Notifications are not configured")]
    NotConfigured,
}

/// Nonexistent/inactive accounts remain indistinguishable from accepted requests.
/// Dependency failures are not evidence that the account does not exist.
pub async fn request(
    state: &crate::state::app::AppState,
    identifier: &str,
) -> Result<(), RecoveryError> {
    use crate::db::{
        entity::{password_reset_tokens, users},
        enums::UserStatus,
    };
    use sea_orm::{ActiveModelTrait, Set, TransactionTrait};
    if !(state.config.notification.available("email")
        || state.config.notification.available("phone"))
    {
        return Err(RecoveryError::NotConfigured);
    }
    let user = users::Entity::find()
        .filter(
            sea_orm::Condition::any()
                .add(users::Column::Email.eq(identifier))
                .add(users::Column::Phone.eq(identifier)),
        )
        .filter(users::Column::DeletedAt.is_null())
        .filter(users::Column::Status.eq(UserStatus::Active))
        .one(&state.db)
        .await?;
    let Some(user) = user else {
        return Ok(());
    };
    let txn = state.db.begin().await?;
    let user = match super::password::PasswordIdentityService::lock_user(&txn, user.id).await {
        Ok(user) if user.status == UserStatus::Active => user,
        Ok(_) | Err(DbErr::RecordNotFound(_)) => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    // Only verified contacts may recover an account; registration alone proves no ownership.
    // Contact changes and issuance use the same user lock.
    let (channel, recipient) =
        if let Some(email) = user.email.as_deref().filter(|email| {
            user.email_verified_at.is_some() && email.eq_ignore_ascii_case(identifier)
        }) {
            ("email", email)
        } else if let Some(phone) = user.phone.as_deref()
            && user.phone_verified_at.is_some()
            && (phone == identifier
                || phone == pero_utils::string::canonical_rate_limit_key(identifier))
        {
            ("phone", phone)
        } else {
            return Ok(());
        };
    if !state.config.notification.available(channel) {
        // A disabled channel must not reveal that this verified contact exists.
        return Ok(());
    }
    let token = pero_utils::oauth::jwt::sign_password_reset_token(
        &user.id.to_string(),
        state.config.password_reset.ttl_seconds as i64,
        state.config.password_reset.signing_key.expose_secret(),
    )?;
    let now = time::OffsetDateTime::now_utc();
    let expires_at =
        super::verification::expires_in_seconds(state.config.password_reset.ttl_seconds);
    password_reset_tokens::ActiveModel {
        id: Set(Uuid::now_v7()),
        user_id: Set(user.id),
        token_hash: Set(pero_utils::crypto::sha256_hex(&token)),
        issued_at: Set(now),
        expires_at: Set(expires_at),
        consumed_at: Set(None),
    }
    .insert(&txn)
    .await?;
    let mut link =
        pero_utils::oauth::url::issuer_endpoint(&state.config.sso.base_url, "sso/reset-password");
    pero_utils::encode::append_query_param(&mut link, "token", &token);
    super::notify::enqueue(
        &txn,
        user.id,
        &super::notify::Notification {
            channel,
            kind: "reset_password",
            to: recipient,
            code: None,
            link: &link,
        },
        expires_at,
    )
    .await?;
    txn.commit().await?;
    Ok(())
}

#[derive(serde::Serialize)]
pub struct Readiness {
    pub password: bool,
    pub oidc: bool,
    pub verified_contact: bool,
    pub password_recovery: bool,
    pub recovery_codes_remaining: usize,
}

pub fn readiness(
    config: &crate::config::AppConfig,
    user: &crate::db::entity::users::Model,
    password: bool,
    oidc: bool,
    recovery_codes_remaining: usize,
) -> Readiness {
    let verified_contact = user.email.is_some() && user.email_verified_at.is_some()
        || user.phone.is_some() && user.phone_verified_at.is_some();
    Readiness {
        password,
        oidc,
        verified_contact,
        recovery_codes_remaining,
        password_recovery: verified_contact
            && ((user.email_verified_at.is_some() && config.notification.available("email"))
                || (user.phone_verified_at.is_some() && config.notification.available("phone"))),
    }
}

/// Issue a short-lived recovery credential without clearing the existing authenticator.
pub async fn issue_assisted_recovery(
    state: &crate::state::app::AppState,
    actor: &crate::state::session::SsoSession,
    target: Uuid,
    reason: &str,
) -> Result<String, super::ManagementError> {
    use crate::db::enums::UserStatus;
    use sea_orm::TransactionTrait;
    let reason = reason.trim();
    if reason.is_empty() || reason.chars().count() > 500 {
        return Err(super::ManagementError::Invalid("recovery_reason_required"));
    }
    let txn = state.db.begin().await?;
    super::admin::lock_policy(&txn).await?;
    super::admin::require_recent_super_admin(&txn, actor, &state.config.sso).await?;
    if actor.user_id == target {
        return Err(super::ManagementError::Invalid("cannot_modify_self"));
    }
    let target = super::password::PasswordIdentityService::lock_user(&txn, target).await?;
    if target.status != UserStatus::Active || !super::security::mfa_enabled(&txn, target.id).await?
    {
        return Err(super::ManagementError::Invalid("mfa_not_enabled"));
    }
    let code = pero_utils::crypto::generate_nonce();
    super::security::execute(&txn,
        "UPDATE user_mfa SET recovery_hashes='{}',pending_secret_enc=NULL,setup_session=NULL,assisted_recovery_hash=$2,assisted_recovery_expires_at=now()+interval '15 minutes' WHERE user_id=$1",
        vec![target.id.into(), pero_utils::crypto::sha256_hex(&code).into()]).await?;
    super::session::SessionService::revoke_all_login_state_for_user_in_db(
        &txn,
        target.id,
        "assisted_mfa_recovery",
    )
    .await?;
    super::security::execute(&txn,
        "INSERT INTO audit_events(actor_id,actor_username,action,target,outcome,http_status,details) SELECT id,username,'admin_mfa_recovery',$2,'success',200,$3 FROM users WHERE id=$1",
        vec![actor.user_id.into(), target.id.to_string().into(),
            serde_json::json!({"reason":{"before":null,"after":reason}}).into()]).await?;
    super::security::notify(&txn, &target, "mfa_recovery").await?;
    txn.commit().await?;
    Ok(code)
}
