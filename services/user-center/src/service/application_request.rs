//! Self-service access for authenticated users of ordinary applications.
use super::{ManagementError as Error, access, permissions, security::execute};
use crate::{
    db::entity::users,
    state::{app::AppState, session::SsoSession},
};
use sea_orm::{ConnectionTrait, DbBackend, FromQueryResult, Statement, TransactionTrait};
use uuid::Uuid;

// Both the portal and authenticated request flow evaluate the effective registration policy.
pub(crate) const ACCESS_MODE_SQL: &str = "CASE
    WHEN COALESCE(p.mode, platform.mode) <> 'self_service' THEN 'managed'
    WHEN COALESCE(p.approval_required, platform.approval_required) THEN 'approval'
    ELSE 'open'
END";

#[derive(FromQueryResult)]
pub struct Policy {
    pub mode: String,
    pub paused: bool,
    pub domains: Vec<String>,
}

pub async fn policy<C: ConnectionTrait>(db: &C, app: Uuid) -> Result<Policy, Error> {
    Policy::find_by_statement(Statement::from_sql_and_values(
        DbBackend::Postgres,
        format!(
            "SELECT {ACCESS_MODE_SQL} AS mode, platform.emergency_stop AS paused,
                    COALESCE(p.domains, platform.domains) AS domains
                 FROM registration_policies platform
                 LEFT JOIN registration_policies p ON p.app_id = $1
                 WHERE platform.app_id IS NULL"
        ),
        [app.into()],
    ))
    .one(db)
    .await?
    .ok_or(Error::Invalid("enrollment_unavailable"))
}

pub(crate) fn check_email_domain(
    domains: &[String],
    user: &users::Model,
) -> Result<(), &'static str> {
    if domains.is_empty() {
        return Ok(());
    }
    let email = super::contact::ContactChannel::Email;
    let address = email
        .current_value(user)
        .filter(|_| email.is_verified(user))
        .ok_or("verified_email_required")?;
    if !super::enrollment::email_domain_allowed(domains, address) {
        return Err("email_domain_not_allowed");
    }
    Ok(())
}

pub(super) async fn close_if_managed<C: ConnectionTrait>(
    db: &C,
    app: Option<Uuid>,
) -> Result<(), sea_orm::DbErr> {
    execute(
        db,
        "UPDATE application_access_requests r SET status = 'closed', updated_at = now()
         FROM registration_policies platform
         LEFT JOIN registration_policies p ON p.app_id = $1
         WHERE platform.app_id IS NULL AND r.status = 'pending'
           AND COALESCE(p.mode, platform.mode) <> 'self_service'
           AND (r.app_id = $1 OR ($1::uuid IS NULL AND NOT EXISTS (
               SELECT 1 FROM registration_policies override
               WHERE override.app_id = r.app_id)))",
        vec![app.into()],
    )
    .await
}

#[derive(FromQueryResult, serde::Serialize)]
pub struct RequestStatus {
    pub status: String,
    pub reason: String,
}

pub async fn current<C: ConnectionTrait>(
    db: &C,
    user: Uuid,
    app: Uuid,
) -> Result<Option<RequestStatus>, sea_orm::DbErr> {
    RequestStatus::find_by_statement(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "SELECT status, reason FROM application_access_requests WHERE user_id = $1 AND app_id = $2",
        [user.into(), app.into()],
    ))
    .one(db)
    .await
}

/// A true result means the caller may continue the normal authorization flow.
pub async fn submit(state: &AppState, session: &SsoSession, app: Uuid) -> Result<bool, Error> {
    let txn = state.db.begin().await?;
    // A first grant has no access row to lock. Serialize its creation with other
    // admission writers before taking the account lock.
    super::admin::lock_policy(&txn).await?;
    let app = access::ordinary_app(&txn, app).await?;
    let existing_access = access::lock_user_app_access(&txn, session.user_id, app.id).await?;
    let user =
        super::account_security::lock_account_session(&txn, session, &state.config.sso).await?;
    if let Some(current) = existing_access {
        if current.status != crate::db::enums::CommonStatus::Active {
            return Err(Error::Invalid("app_access_disabled"));
        }
        if current.admission_origin == "explicit" {
            return Ok(true);
        }
    }
    let policy = policy(&txn, app.id).await?;
    if app.tenant_mode == "organization" || policy.paused || policy.mode == "managed" {
        return Err(Error::Invalid("registration_closed"));
    }
    check_email_domain(&policy.domains, &user).map_err(Error::Invalid)?;
    if policy.mode == "open" {
        access::grant_explicit(
            &txn,
            session.user_id,
            app.id,
            session.user_id,
            "app_access_self_service",
            false,
        )
        .await?;
        txn.commit().await?;
        return Ok(true);
    }
    let id = Uuid::now_v7();
    let inserted = txn
        .execute_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "INSERT INTO application_access_requests (id, user_id, app_id) VALUES ($1, $2, $3)
             ON CONFLICT (user_id, app_id) DO UPDATE SET id = EXCLUDED.id, status = 'pending',
                 decided_by = NULL, reason = '', created_at = now(), updated_at = now()
             WHERE CASE application_access_requests.status
                 WHEN 'pending' THEN false
                 WHEN 'rejected' THEN application_access_requests.updated_at <= now() - interval '5 minutes'
                 WHEN 'closed' THEN application_access_requests.updated_at <= now() - interval '10 seconds'
                 ELSE true
             END",
            [id.into(), session.user_id.into(), app.id.into()],
        ))
        .await?
        .rows_affected();
    if inserted == 0 {
        return if current(&txn, session.user_id, app.id)
            .await?
            .is_some_and(|r| r.status == "pending")
        {
            Ok(false)
        } else {
            Err(Error::Invalid("rate_limited"))
        };
    }
    access::audit(
        &txn,
        session.user_id,
        session.user_id,
        app.id,
        "app_access_requested",
        serde_json::json!({"request_id": id}),
    )
    .await?;
    txn.commit().await?;
    Ok(false)
}

pub async fn withdraw(state: &AppState, session: &SsoSession, app: Uuid) -> Result<(), Error> {
    let txn = state.db.begin().await?;
    super::admin::read_lock_policy(&txn).await?;
    access::ordinary_app(&txn, app).await?;
    super::account_security::lock_account_session(&txn, session, &state.config.sso).await?;
    if close(&txn, Some(session.user_id), Some(app)).await? > 0 {
        access::audit(
            &txn,
            session.user_id,
            session.user_id,
            app,
            "app_access_request_withdrawn",
            serde_json::json!({}),
        )
        .await?;
    }
    txn.commit().await?;
    Ok(())
}

pub(super) async fn close<C: ConnectionTrait>(
    db: &C,
    user: Option<Uuid>,
    app: Option<Uuid>,
) -> Result<u64, sea_orm::DbErr> {
    db.execute_raw(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "UPDATE application_access_requests SET status = 'closed', updated_at = now()
         WHERE status = 'pending' AND ($1::uuid IS NULL OR user_id = $1) AND ($2::uuid IS NULL OR app_id = $2)",
        [user.into(), app.into()],
    ))
    .await
    .map(|result| result.rows_affected())
}

#[derive(FromQueryResult, serde::Serialize)]
pub struct PendingRequest {
    pub id: Uuid,
    pub username: String,
}

pub async fn pending<C: ConnectionTrait>(
    db: &C,
    app: Uuid,
    page: u64,
    include_admins: bool,
) -> Result<(Vec<PendingRequest>, bool), sea_orm::DbErr> {
    let size = crate::config::DASHBOARD_PAGE_SIZE as i64;
    let mut rows = PendingRequest::find_by_statement(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "SELECT r.id, u.username::text FROM application_access_requests r JOIN users u ON u.id = r.user_id
         WHERE r.app_id = $1 AND r.status = 'pending'
           AND ($4 OR NOT EXISTS (SELECT 1 FROM admin_roles a WHERE a.user_id = r.user_id))
         ORDER BY r.created_at, r.id LIMIT $2 OFFSET $3",
        [app.into(), (size + 1).into(), ((page as i64 - 1) * size).into(), include_admins.into()],
    )).all(db).await?;
    let has_more = rows.len() > size as usize;
    rows.truncate(size as usize);
    Ok((rows, has_more))
}

pub async fn review(
    state: &AppState,
    actor: &permissions::Actor,
    app: Uuid,
    request: Uuid,
    approve: bool,
    reason: &str,
) -> Result<(), Error> {
    let txn = state.db.begin().await?;
    let permission = permissions::authorize(&txn, actor).await?;
    permissions::app(
        &txn,
        &permission,
        app,
        permissions::Permission::AppsMembersManage,
    )
    .await?;
    let application = access::ordinary_app(&txn, app).await?;
    let user: Uuid = txn.query_one_raw(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "SELECT user_id FROM application_access_requests WHERE id = $1 AND app_id = $2 AND status = 'pending'",
        [request.into(), app.into()],
    )).await?.ok_or(Error::Invalid("request_not_pending"))?.try_get("", "user_id")?;
    if actor.session.user_id == user || reason.chars().count() > 500 {
        return Err(Error::Invalid("invalid_request"));
    }
    permissions::protect_user(&txn, &permission, user).await?;
    if approve {
        let policy = policy(&txn, app).await?;
        if application.tenant_mode == "organization" || policy.paused || policy.mode == "managed" {
            return Err(Error::Invalid("registration_closed"));
        }
        if !policy.domains.is_empty() {
            // Match the app/access/user lock order used by token issuance.
            access::lock_user_app_access(&txn, user, app).await?;
            let applicant = super::password::PasswordIdentityService::lock_user(&txn, user).await?;
            check_email_domain(&policy.domains, &applicant).map_err(Error::Invalid)?;
        }
        let approved = access::grant_explicit(
            &txn,
            user,
            app,
            actor.session.user_id,
            "app_access_approved",
            false,
        )
        .await?;
        if approved != Some(request) {
            return Err(Error::Invalid("request_not_pending"));
        }
    } else {
        let rejected = txn
            .execute_raw(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "UPDATE application_access_requests SET status = 'rejected', decided_by = $2,
             reason = $3, updated_at = now() WHERE id = $1 AND status = 'pending'",
                [
                    request.into(),
                    actor.session.user_id.into(),
                    reason.trim().into(),
                ],
            ))
            .await?
            .rows_affected();
        if rejected == 0 {
            return Err(Error::Invalid("request_not_pending"));
        }
        access::audit(
            &txn,
            actor.session.user_id,
            user,
            app,
            "app_access_rejected",
            serde_json::json!({"request_id": request, "reason": reason.trim()}),
        )
        .await?;
    }
    txn.commit().await?;
    Ok(())
}
