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
    txn.commit().await?;
    Ok(())
}

async fn lock_account_session<C: ConnectionTrait>(
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
