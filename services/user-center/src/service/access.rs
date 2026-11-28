use super::permissions::{self, Actor, Permission as P};
use sea_orm::{
    ColumnTrait, ConnectionTrait, DatabaseConnection, DatabaseTransaction, DbBackend, EntityTrait,
    QueryFilter, QuerySelect, Statement, TransactionTrait,
};
use uuid::Uuid;

use super::ManagementError;
use crate::db::entity::{apps as apps_entity, user_app_access as uaa, users};
use crate::db::enums::CommonStatus;

async fn lock_app_for_access_change(
    txn: &DatabaseTransaction,
    user_id: Uuid,
    app_id: Uuid,
) -> Result<users::Model, ManagementError> {
    // Match token issuance's app -> access lock order.
    apps_entity::Entity::find_by_id(app_id)
        .lock_shared()
        .one(txn)
        .await?
        .ok_or(ManagementError::Invalid("invalid_app_id"))?;
    let user = users::Entity::find_by_id(user_id)
        .filter(users::Column::DeletedAt.is_null())
        .one(txn)
        .await?
        .ok_or(ManagementError::Invalid("not_found"))?;
    Ok(user)
}

pub async fn grant_app(
    db: &DatabaseConnection,
    actor: &Actor,
    user_id: Uuid,
    app_id: Uuid,
) -> Result<(), ManagementError> {
    manage_grant(db, actor, user_id, app_id, false).await
}

pub async fn restore_app(
    db: &DatabaseConnection,
    actor: &Actor,
    user_id: Uuid,
    app_id: Uuid,
) -> Result<(), ManagementError> {
    manage_grant(db, actor, user_id, app_id, true).await
}

async fn manage_grant(
    db: &DatabaseConnection,
    actor: &Actor,
    user_id: Uuid,
    app_id: Uuid,
    restore: bool,
) -> Result<(), ManagementError> {
    let txn = db.begin().await?;
    let access = permissions::authorize(&txn, actor).await?;
    permissions::app(&txn, &access, app_id, P::AppsMembersManage).await?;
    permissions::protect_user(&txn, &access, user_id).await?;

    let app = apps_entity::Entity::find_by_id(app_id)
        .lock_shared()
        .one(&txn)
        .await?
        .ok_or(ManagementError::Invalid("invalid_app_id"))?;
    if !app.system
        && (app.status != CommonStatus::Active
            || super::application_request::policy(&txn, app_id)
                .await?
                .paused)
    {
        return Err(ManagementError::Invalid("registration_closed"));
    }
    let action = if restore {
        "app_access_restored"
    } else {
        "app_access_granted"
    };
    grant_explicit(
        &txn,
        user_id,
        app_id,
        actor.session.user_id,
        action,
        restore,
    )
    .await?;
    txn.commit().await?;
    Ok(())
}

pub(super) async fn ordinary_app<C: ConnectionTrait>(
    db: &C,
    app_id: Uuid,
) -> Result<apps_entity::Model, ManagementError> {
    apps_entity::Entity::find_by_id(app_id)
        .lock_shared()
        .one(db)
        .await?
        .filter(|app| !app.system && app.status == CommonStatus::Active)
        .ok_or(ManagementError::Invalid("enrollment_unavailable"))
}

pub(super) async fn lock_user_app_access<C: ConnectionTrait>(
    db: &C,
    user_id: Uuid,
    app_id: Uuid,
) -> Result<Option<uaa::Model>, sea_orm::DbErr> {
    uaa::Entity::find_by_id((user_id, app_id))
        .lock_exclusive()
        .one(db)
        .await
}

/// The caller holds the policy lock and has authorized this source of access.
pub(super) async fn grant_explicit(
    db: &DatabaseTransaction,
    user: Uuid,
    app: Uuid,
    actor: Uuid,
    action: &str,
    restore: bool,
) -> Result<Option<Uuid>, ManagementError> {
    if !users::Entity::find_by_id(user)
        .one(db)
        .await?
        .is_some_and(|u| u.deleted_at.is_none() && u.status == crate::db::enums::UserStatus::Active)
    {
        return Err(ManagementError::Invalid("not_found"));
    }
    let statement = if restore {
        "UPDATE user_app_access SET status = 'active', admission_origin = 'explicit', updated_at = now()
         WHERE user_id = $1 AND app_id = $2 AND status = 'disabled'"
    } else {
        "INSERT INTO user_app_access (user_id, app_id) VALUES ($1, $2)
         ON CONFLICT (user_id, app_id) DO UPDATE SET status = 'active',
             admission_origin = 'explicit', updated_at = now()
         WHERE user_app_access.status = 'active'"
    };
    let written = db
        .execute_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            statement,
            [user.into(), app.into()],
        ))
        .await?
        .rows_affected();
    if written == 0 {
        return Err(ManagementError::Invalid(if restore {
            "app_access_not_disabled"
        } else {
            "app_access_disabled"
        }));
    }
    Ok(record_explicit_grant(db, user, app, actor, action, serde_json::json!({})).await?)
}

pub(super) async fn record_explicit_grant(
    db: &DatabaseTransaction,
    user: Uuid,
    app: Uuid,
    actor: Uuid,
    action: &str,
    mut details: serde_json::Value,
) -> Result<Option<Uuid>, sea_orm::DbErr> {
    let request: Option<Uuid> = db.query_one_raw(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "UPDATE application_access_requests SET status = 'approved', decided_by = $3, updated_at = now()
         WHERE user_id = $1 AND app_id = $2 AND status = 'pending' RETURNING id",
        [user.into(), app.into(), actor.into()],
    )).await?.map(|row| row.try_get("", "id")).transpose()?;
    if let Some(id) = request {
        details["request_id"] = serde_json::json!(id);
    }
    audit(db, actor, user, app, action, details).await?;
    Ok(request)
}

pub(super) async fn audit<C: ConnectionTrait>(
    db: &C,
    actor: Uuid,
    user: Uuid,
    app: Uuid,
    action: &str,
    details: serde_json::Value,
) -> Result<(), sea_orm::DbErr> {
    super::security::execute(
        db,
        "INSERT INTO audit_events (actor_id, actor_username, action, target, outcome, http_status, details)
         SELECT id, username, $2, $3, 'success', 200, $4 FROM users WHERE id = $1",
        vec![actor.into(), action.into(), format!("{app}/{user}").into(), details.into()],
    )
    .await
}

pub(super) async fn revoke_explicit(
    db: &DatabaseTransaction,
    user: Uuid,
    app: Uuid,
    reason: &str,
) -> Result<(), sea_orm::DbErr> {
    // Keep a denial even if no access has been granted yet.
    super::security::execute(
        db,
        "INSERT INTO user_app_access (user_id, app_id, status) VALUES ($1, $2, 'disabled')
         ON CONFLICT (user_id, app_id) DO UPDATE SET status = 'disabled',
             admission_origin = 'explicit', updated_at = now()",
        vec![user.into(), app.into()],
    )
    .await?;
    super::application_request::close(db, Some(user), Some(app)).await?;
    super::session::SessionService::revoke_app_grants(db, app, Some(user), reason).await
}

async fn current_admission<C: ConnectionTrait>(
    db: &C,
    access: &uaa::Model,
) -> Result<bool, sea_orm::DbErr> {
    if access.status != CommonStatus::Active {
        return Ok(false);
    }
    if access.admission_origin == "explicit" {
        return Ok(true);
    }
    super::tenant_context::auto_eligible(db, access.user_id, access.app_id).await
}

pub(crate) async fn has_oauth_app_access(
    db: &DatabaseConnection,
    user: Uuid,
    app: Uuid,
) -> Result<bool, sea_orm::DbErr> {
    match active_app_access(db, user, app).await? {
        Some(access) => current_admission(db, &access).await,
        None => Ok(false),
    }
}

/// Interactive OAuth can activate organization-derived access.
pub async fn ensure_oauth_app_access(
    db: &DatabaseConnection,
    session: &crate::state::session::SsoSession,
    app_id: Uuid,
    idle_ttl_seconds: u64,
) -> Result<bool, sea_orm::DbErr> {
    let txn = db.begin().await?;
    super::admin::read_lock_policy(&txn).await?;
    let app = apps_entity::Entity::find_by_id(app_id)
        .lock_shared()
        .one(&txn)
        .await?;
    let Some(app) = app.filter(|app| !app.system && app.status == CommonStatus::Active) else {
        return Ok(false);
    };
    // Recheck admission under the app/access locks: a concurrent grant may have
    // completed since the initial read. Existing denials remain authoritative.
    if let Some(access) = lock_user_app_access(&txn, session.user_id, app_id).await? {
        return current_admission(&txn, &access).await;
    }
    if !app.organization_auto_access
        || !super::tenant_context::auto_eligible(&txn, session.user_id, app_id).await?
    {
        return Ok(false);
    }
    let user = users::Entity::find_by_id(session.user_id)
        .lock_shared()
        .one(&txn)
        .await?;
    if !user
        .is_some_and(|u| u.deleted_at.is_none() && u.status == crate::db::enums::UserStatus::Active)
    {
        return Ok(false);
    }
    let live_session = crate::db::helper::session::primary_query(
        time::OffsetDateTime::now_utc(),
        idle_ttl_seconds,
    )
    .filter(crate::db::entity::sso_sessions::Column::Id.eq(session.id))
    .filter(crate::db::entity::sso_sessions::Column::UserId.eq(session.user_id))
    .lock_shared()
    .one(&txn)
    .await?;
    if live_session.is_none() {
        return Ok(false);
    }
    txn.execute_raw(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "INSERT INTO user_app_access (user_id, app_id, admission_origin)
         SELECT $1, $2, 'organization' FROM registration_policies
         WHERE app_id IS NULL AND NOT emergency_stop
         ON CONFLICT DO NOTHING",
        [session.user_id.into(), app_id.into()],
    ))
    .await?;
    txn.commit().await?;
    has_oauth_app_access(db, session.user_id, app_id).await
}

pub(crate) async fn can_open_super_admin_access<C: ConnectionTrait>(
    db: &C,
    user: Uuid,
    app: Uuid,
) -> Result<bool, sea_orm::DbErr> {
    db.query_one_raw(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "SELECT 1 FROM admin_roles r JOIN apps a ON a.id = $2
         WHERE r.user_id = $1 AND r.role = 'super_admin' AND NOT a.system AND a.status = 'active'
           AND EXISTS (SELECT 1 FROM registration_policies WHERE app_id IS NULL AND NOT emergency_stop)
           AND NOT EXISTS (SELECT 1 FROM user_app_access WHERE user_id = $1 AND app_id = $2)",
        [user.into(), app.into()],
    ))
    .await
    .map(|row| row.is_some())
}

/// The OAuth issuance transaction holds the policy lock and validates the session and tenant.
pub(super) async fn open_super_admin_access(
    db: &DatabaseTransaction,
    user: Uuid,
    app: Uuid,
) -> Result<bool, sea_orm::DbErr> {
    apps_entity::Entity::find_by_id(app)
        .lock_shared()
        .one(db)
        .await?;
    if !can_open_super_admin_access(db, user, app).await? {
        return Ok(false);
    }
    db.execute_raw(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "INSERT INTO user_app_access (user_id, app_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
        [user.into(), app.into()],
    ))
    .await
    .map(|result| result.rows_affected() > 0)
}

pub async fn revoke_app(
    db: &DatabaseConnection,
    actor: &Actor,
    user_id: Uuid,
    app_id: Uuid,
) -> Result<(), ManagementError> {
    let txn = db.begin().await?;
    let access = permissions::authorize(&txn, actor).await?;
    permissions::app(&txn, &access, app_id, P::AppsMembersManage).await?;
    permissions::protect_user(&txn, &access, user_id).await?;

    lock_app_for_access_change(&txn, user_id, app_id).await?;
    revoke_explicit(&txn, user_id, app_id, "app_access_revoked").await?;
    txn.commit().await?;
    Ok(())
}

pub async fn active_app_access<C: ConnectionTrait>(
    db: &C,
    user_id: Uuid,
    app_id: Uuid,
) -> Result<Option<uaa::Model>, sea_orm::DbErr> {
    uaa::Entity::find_by_id((user_id, app_id))
        .filter(uaa::Column::Status.eq(CommonStatus::Active))
        .inner_join(apps_entity::Entity)
        .filter(apps_entity::Column::Status.eq(CommonStatus::Active))
        .one(db)
        .await
}

pub struct GrantAccess {
    pub(crate) user: users::Model,
    pub(crate) app: apps_entity::Model,
    pub(crate) token_version: i64,
}

/// Lock policy rows before a grant row so revocation cannot miss a concurrent issuance.
pub async fn lock_grant_access<C: ConnectionTrait>(
    db: &C,
    user_id: Uuid,
    app_id: Uuid,
) -> Result<Option<GrantAccess>, sea_orm::DbErr> {
    use crate::db::enums::UserStatus;
    let app = apps_entity::Entity::find_by_id(app_id)
        .lock_shared()
        .one(db)
        .await?;
    let Some(app) = app.filter(|app| app.status == CommonStatus::Active) else {
        return Ok(None);
    };
    let access = uaa::Entity::find_by_id((user_id, app_id))
        .lock_exclusive()
        .one(db)
        .await?;
    let Some(access) = access.filter(|access| access.status == CommonStatus::Active) else {
        return Ok(None);
    };
    let user = users::Entity::find_by_id(user_id)
        .lock_shared()
        .one(db)
        .await?;
    Ok(user
        .filter(|user| user.deleted_at.is_none() && user.status == UserStatus::Active)
        .map(|user| GrantAccess {
            user,
            app,
            token_version: access.token_version,
        }))
}
