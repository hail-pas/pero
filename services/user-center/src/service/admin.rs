//! Fixed administrator identities and serialized policy changes.
use super::{ManagementError, security as sec};
use crate::{
    db::{entity::users, enums::UserStatus},
    state::session::SsoSession,
};
use sea_orm::{
    ColumnTrait, ConnectionTrait, DatabaseConnection, DbBackend, EntityTrait, FromQueryResult,
    QueryFilter, Statement, TransactionTrait,
};
use uuid::Uuid;

/// Shared dashboard entitlement. MFA is enforced separately as an authentication step.
pub async fn can_access_dashboard<C: ConnectionTrait>(
    db: &C,
    user: Uuid,
) -> Result<bool, sea_orm::DbErr> {
    Ok(matches!(
        sec::role(db, user).await?.as_deref(),
        Some("super_admin" | "admin")
    ))
}

pub async fn lock_policy<C: ConnectionTrait>(db: &C) -> Result<(), sea_orm::DbErr> {
    sec::execute(db, "SELECT pg_advisory_xact_lock(71234019)", vec![]).await
}
/// Call under the policy lock when removing a role or disabling its account.
pub async fn protect_last_super_admin<C: ConnectionTrait>(
    db: &C,
    user: Uuid,
) -> Result<(), ManagementError> {
    if sec::role(db, user).await?.as_deref() != Some("super_admin") {
        return Ok(());
    }
    #[derive(FromQueryResult)]
    struct Count {
        count: i64,
    }
    let count=Count::find_by_statement(Statement::from_sql_and_values(DbBackend::Postgres,
        "SELECT count(*) AS count FROM admin_roles r JOIN users u ON u.id=r.user_id WHERE role='super_admin' AND u.status='active' AND u.deleted_at IS NULL AND r.user_id<>$1",[user.into()]))
        .one(db).await?.ok_or(ManagementError::Invalid("not_found"))?.count;
    if count == 0 {
        return Err(ManagementError::Invalid("last_super_admin"));
    }
    Ok(())
}
pub async fn update_role(
    db: &DatabaseConnection,
    actor: &SsoSession,
    idle_ttl_seconds: u64,
    username: &str,
    role: &str,
) -> Result<(), ManagementError> {
    if !matches!(role, "super_admin" | "admin" | "remove") {
        return Err(ManagementError::Invalid("invalid_request"));
    }
    let txn = db.begin().await?;
    let access = super::permissions::authorize(
        &txn,
        &super::permissions::Actor {
            session: actor.clone(),
            idle_ttl_seconds,
        },
    )
    .await?;
    if !access.super_admin {
        return Err(ManagementError::Invalid("forbidden"));
    }
    let mut query = users::Entity::find()
        .filter(users::Column::Username.eq(username.trim()))
        .filter(users::Column::DeletedAt.is_null());
    if role != "remove" {
        query = query.filter(users::Column::Status.eq(UserStatus::Active));
    }
    let user = query
        .one(&txn)
        .await?
        .ok_or(ManagementError::Invalid("not_found"))?;
    if user.id == actor.user_id {
        return Err(ManagementError::Invalid("cannot_change_own_admin_role"));
    }
    super::password::PasswordIdentityService::lock_user(&txn, user.id).await?;
    if role != "super_admin" {
        protect_last_super_admin(&txn, user.id).await?;
    }
    if sec::role(&txn, user.id).await?.as_deref() != Some(role) {
        sec::execute(
            &txn,
            "DELETE FROM admin_permission_state WHERE user_id=$1",
            vec![user.id.into()],
        )
        .await?;
    }
    if role == "remove" {
        sec::execute(
            &txn,
            "DELETE FROM admin_roles WHERE user_id=$1",
            vec![user.id.into()],
        )
        .await?;
    } else {
        sec::execute(&txn,"INSERT INTO admin_roles(user_id,role) VALUES($1,$2) ON CONFLICT(user_id) DO UPDATE SET role=EXCLUDED.role",vec![user.id.into(),role.into()]).await?;
    }
    if sec::role(&txn, user.id).await?.as_deref() == Some("admin") {
        sec::execute(
            &txn,
            "INSERT INTO admin_permission_state(user_id) VALUES($1) ON CONFLICT DO NOTHING",
            vec![user.id.into()],
        )
        .await?;
    } else {
        sec::execute(
            &txn,
            "DELETE FROM admin_permission_state WHERE user_id=$1",
            vec![user.id.into()],
        )
        .await?;
    }
    if role != "super_admin" {
        super::enrollment::invalidate_sponsor(&txn, user.id).await?;
    }
    super::session::SessionService::revoke_all_login_state_for_user_in_db(
        &txn,
        user.id,
        "admin_role_changed",
    )
    .await?;
    txn.commit().await?;
    Ok(())
}

/// Call inside a transaction under the policy lock for administrative security interventions.
pub async fn require_recent_super_admin(
    db: &sea_orm::DatabaseTransaction,
    actor: &SsoSession,
    config: &crate::config::SsoConfig,
) -> Result<(), ManagementError> {
    super::account_security::lock_account_session(db, actor, config).await?;
    if sec::role(db, actor.user_id).await?.as_deref() != Some("super_admin") {
        return Err(ManagementError::Invalid("forbidden"));
    }
    if !sec::recent(db, actor.id, config.session_idle_ttl_seconds).await? {
        return Err(ManagementError::Invalid("reauth_required"));
    }
    Ok(())
}
