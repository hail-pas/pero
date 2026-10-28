use sea_orm::{
    ActiveModelTrait, ColumnTrait, Condition, ConnectionTrait, DatabaseConnection, EntityTrait,
    QueryFilter, QuerySelect, QueryTrait, Set, TransactionTrait, sea_query::Expr,
};
use time::OffsetDateTime;
use uuid::Uuid;

use super::{ManagementError, password::PasswordIdentityService, session::SessionService};
use crate::db::entity::{
    apps, identities, identity_providers, oauth_clients, refresh_tokens, sso_sessions,
    user_app_access, user_consents,
};
use crate::db::enums::{IdentityKind, UserStatus};

/// The selection is always intersected with the authenticated user's sessions.
pub async fn revoke_sessions<C: ConnectionTrait>(
    db: &C,
    user_id: Uuid,
    selection: Condition,
    reason: &str,
) -> Result<(), sea_orm::DbErr> {
    let filter = Condition::all()
        .add(sso_sessions::Column::UserId.eq(user_id))
        .add(selection);
    let ids = sso_sessions::Entity::find()
        .select_only()
        .column(sso_sessions::Column::Id)
        .filter(filter.clone())
        .into_query();
    let now = OffsetDateTime::now_utc();
    sso_sessions::Entity::update_many()
        .col_expr(sso_sessions::Column::RevokedAt, Expr::value(Some(now)))
        .col_expr(sso_sessions::Column::RevokeReason, Expr::value(reason))
        .filter(filter)
        .filter(sso_sessions::Column::RevokedAt.is_null())
        .exec(db)
        .await?;
    refresh_tokens::Entity::update_many()
        .col_expr(refresh_tokens::Column::RevokedAt, Expr::value(Some(now)))
        .col_expr(refresh_tokens::Column::RevokeReason, Expr::value(reason))
        .filter(refresh_tokens::Column::UserId.eq(user_id))
        .filter(refresh_tokens::Column::SessionId.in_subquery(ids))
        .filter(refresh_tokens::Column::RevokedAt.is_null())
        .exec(db)
        .await?;
    Ok(())
}

/// Withdraw consent and existing grants without removing the user's app access eligibility.
pub async fn revoke_authorization(
    db: &DatabaseConnection,
    session: &crate::state::session::SsoSession,
    config: &crate::config::SsoConfig,
    app_id: Uuid,
) -> Result<(), ManagementError> {
    let user_id = session.user_id;
    let txn = db.begin().await?;
    apps::Entity::find_by_id(app_id)
        .lock_shared()
        .one(&txn)
        .await?
        .ok_or(ManagementError::Invalid("not_found"))?;
    // Match grant issuance's app -> access -> user -> grant lock order.
    user_app_access::Entity::find_by_id((user_id, app_id))
        .lock_exclusive()
        .one(&txn)
        .await?;
    lock_account_session(&txn, session, config).await?;
    SessionService::revoke_app_grants(&txn, app_id, Some(user_id), "consent_revoked").await?;
    let clients = oauth_clients::Entity::find()
        .select_only()
        .column(oauth_clients::Column::Id)
        .filter(oauth_clients::Column::AppId.eq(app_id))
        .into_query();
    user_consents::Entity::delete_many()
        .filter(user_consents::Column::UserId.eq(user_id))
        .filter(user_consents::Column::ClientId.in_subquery(clients))
        .exec(&txn)
        .await?;
    txn.commit().await?;
    Ok(())
}

pub async fn unlink_identity(
    db: &DatabaseConnection,
    session: &crate::state::session::SsoSession,
    config: &crate::config::SsoConfig,
    identity_id: Uuid,
) -> Result<(), ManagementError> {
    let user_id = session.user_id;
    let txn = db.begin().await?;
    lock_account_session(&txn, session, config).await?;
    let identity = identities::Entity::find_by_id(identity_id)
        .filter(identities::Column::UserId.eq(user_id))
        .filter(identities::Column::Kind.eq(IdentityKind::Oauth))
        .filter(identities::Column::UnboundAt.is_null())
        .one(&txn)
        .await?
        .ok_or(ManagementError::Invalid("not_found"))?;
    let remaining = identities::Entity::find()
        .filter(identities::Column::UserId.eq(user_id))
        .filter(identities::Column::Id.ne(identity_id))
        .filter(identities::Column::UnboundAt.is_null())
        .find_also_related(identity_providers::Entity)
        .all(&txn)
        .await?;
    if !remaining.iter().any(|(identity, provider)| {
        if identity.kind == IdentityKind::Password {
            identity
                .password_hash
                .as_ref()
                .is_some_and(|hash| !hash.is_empty())
        } else {
            provider.as_ref().is_some_and(|provider| provider.enabled)
        }
    }) {
        return Err(ManagementError::Invalid("last_login_identity"));
    }
    let now = OffsetDateTime::now_utc();
    let mut active: identities::ActiveModel = identity.into();
    active.unbound_at = Set(Some(now));
    active.updated_at = Set(now);
    active.update(&txn).await?;
    revoke_sessions(
        &txn,
        user_id,
        Condition::all().add(sso_sessions::Column::IdentityId.eq(identity_id)),
        "identity_unlinked",
    )
    .await?;
    let user = crate::db::entity::users::Entity::find_by_id(user_id)
        .one(&txn)
        .await?
        .ok_or(ManagementError::Invalid("not_found"))?;
    super::security::notify(&txn, &user, "identity_unlinked").await?;
    txn.commit().await?;
    Ok(())
}

pub(crate) async fn lock_account_session<C: ConnectionTrait>(
    db: &C,
    session: &crate::state::session::SsoSession,
    config: &crate::config::SsoConfig,
) -> Result<(), ManagementError> {
    let user = PasswordIdentityService::lock_user(db, session.user_id).await?;
    if user.status != UserStatus::Active
        || crate::db::helper::session::lock_active(
            db,
            session.id,
            session.user_id,
            config.session_idle_ttl_seconds,
        )
        .await?
        .is_none()
    {
        return Err(ManagementError::Invalid("unauthorized"));
    }
    Ok(())
}

pub async fn revoke_account_sessions(
    db: &DatabaseConnection,
    session: &crate::state::session::SsoSession,
    config: &crate::config::SsoConfig,
    selection: Condition,
) -> Result<(), ManagementError> {
    let txn = db.begin().await?;
    lock_account_session(&txn, session, config).await?;
    revoke_sessions(&txn, session.user_id, selection, "user_revoked").await?;
    txn.commit().await?;
    Ok(())
}

/// Remove membership, consent and issued credentials together; keep the shared account.
pub async fn leave_app(
    state: &crate::state::app::AppState,
    session: &crate::state::session::SsoSession,
    app_id: Uuid,
) -> Result<(), ManagementError> {
    let txn = state.db.begin().await?;
    super::admin::lock_policy(&txn).await?;
    let app = apps::Entity::find_by_id(app_id)
        .lock_shared()
        .one(&txn)
        .await?
        .ok_or(ManagementError::Invalid("not_found"))?;
    if app.system {
        return Err(ManagementError::Invalid("system_app_protected"));
    }
    user_app_access::Entity::find_by_id((session.user_id, app_id))
        .lock_exclusive()
        .one(&txn)
        .await?;
    lock_account_session(&txn, session, &state.config.sso).await?;
    user_app_access::Entity::update_many()
        .col_expr(
            user_app_access::Column::Status,
            Expr::value(crate::db::enums::CommonStatus::Disabled),
        )
        .filter(user_app_access::Column::UserId.eq(session.user_id))
        .filter(user_app_access::Column::AppId.eq(app_id))
        .exec(&txn)
        .await?;
    SessionService::revoke_app_grants(&txn, app_id, Some(session.user_id), "membership_withdrawn")
        .await?;
    super::security::execute(&txn,"DELETE FROM user_consents WHERE user_id=$1 AND client_id IN (SELECT id FROM oauth_clients WHERE app_id=$2)",vec![session.user_id.into(),app_id.into()]).await?;
    super::security::execute(&txn,"INSERT INTO audit_events(actor_id,actor_username,action,target,outcome,http_status) SELECT id,username,'membership_withdrawn',$2,'success',200 FROM users WHERE id=$1",vec![session.user_id.into(),app_id.to_string().into()]).await?;
    txn.commit().await?;
    Ok(())
}

/// Require recent authentication and remove identifying data while retaining audit references.
pub async fn close_account(
    state: &crate::state::app::AppState,
    session: &crate::state::session::SsoSession,
    confirmation: &str,
) -> Result<(), ManagementError> {
    let txn = state.db.begin().await?;
    super::admin::lock_policy(&txn).await?;
    let access = user_app_access::Entity::find()
        .filter(user_app_access::Column::UserId.eq(session.user_id))
        .all(&txn)
        .await?;
    let mut app_ids = access.iter().map(|a| a.app_id).collect::<Vec<_>>();
    app_ids.sort();
    for id in app_ids {
        apps::Entity::find_by_id(id).lock_shared().one(&txn).await?;
        user_app_access::Entity::find_by_id((session.user_id, id))
            .lock_exclusive()
            .one(&txn)
            .await?;
    }
    lock_account_session(&txn, session, &state.config.sso).await?;
    if !super::security::recent(&txn, session.id, state.config.sso.session_idle_ttl_seconds).await?
    {
        return Err(ManagementError::Invalid("reauth_required"));
    }
    if super::security::role(&txn, session.user_id)
        .await?
        .is_some()
    {
        return Err(ManagementError::Invalid("remove_admin_role_first"));
    }
    let user = crate::db::entity::users::Entity::find_by_id(session.user_id)
        .one(&txn)
        .await?
        .ok_or(ManagementError::Invalid("not_found"))?;
    if confirmation != user.username {
        return Err(ManagementError::Invalid("confirmation_mismatch"));
    }
    SessionService::revoke_all_login_state_for_user_in_db(&txn, user.id, "account_closed").await?;
    super::contact::invalidate_contact_credentials(&txn, user.id, None).await?;
    super::security::execute(&txn,"DELETE FROM notification_outbox WHERE user_id=$1 OR enrollment_id IN (SELECT id FROM enrollments WHERE email=$2)",vec![user.id.into(),user.email.clone().into()]).await?;
    super::security::execute(&txn,"UPDATE enrollments SET status='revoked' WHERE email=$1 AND status IN ('pending_verification','pending_approval','ready')",vec![user.email.clone().into()]).await?;
    super::security::execute(&txn,"UPDATE user_app_access SET status='disabled',token_version=token_version+1,updated_at=now() WHERE user_id=$1",vec![user.id.into()]).await?;
    super::security::execute(
        &txn,
        "DELETE FROM user_consents WHERE user_id=$1",
        vec![user.id.into()],
    )
    .await?;
    super::security::execute(
        &txn,
        "DELETE FROM identities WHERE user_id=$1",
        vec![user.id.into()],
    )
    .await?;
    super::security::execute(
        &txn,
        "DELETE FROM user_mfa WHERE user_id=$1",
        vec![user.id.into()],
    )
    .await?;
    super::security::execute(&txn,"INSERT INTO audit_events(actor_id,actor_username,action,target,outcome,http_status) VALUES($1,$2,'account_closed','/account/close','success',200)",vec![user.id.into(),user.username.clone().into()]).await?;
    super::security::execute(&txn,"UPDATE users SET status='disabled',deleted_at=now(),updated_at=now(),username=$2,email=NULL,email_verified_at=NULL,phone=NULL,phone_verified_at=NULL,nickname=NULL,avatar_url=NULL WHERE id=$1",vec![user.id.into(),format!("deleted_{}",user.id.simple()).into()]).await?;
    txn.commit().await?;
    Ok(())
}
