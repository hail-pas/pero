//! The two fixed roles deliberately do not implement a general permission system.
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
    lock_policy(&txn).await?;
    let actor_user =
        super::password::PasswordIdentityService::lock_user(&txn, actor.user_id).await?;
    if actor_user.status != UserStatus::Active
        || sec::role(&txn, actor.user_id).await?.as_deref() != Some("super_admin")
    {
        return Err(ManagementError::Invalid("forbidden"));
    }
    if !sec::recent(&txn, actor.id, idle_ttl_seconds).await? {
        return Err(ManagementError::Invalid("reauth_required"));
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
    super::password::PasswordIdentityService::lock_user(&txn, user.id).await?;
    if role != "super_admin" {
        protect_last_super_admin(&txn, user.id).await?;
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
    super::session::SessionService::revoke_all_login_state_for_user_in_db(
        &txn,
        user.id,
        "admin_role_changed",
    )
    .await?;
    txn.commit().await?;
    Ok(())
}
