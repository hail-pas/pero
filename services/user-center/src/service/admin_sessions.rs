//! Administrative interventions reuse account credential locks, recent authentication and revocation.
use super::{ManagementError, security as sec};
use crate::{
    db::entity::sso_sessions,
    state::{app::AppState, session::SsoSession},
};
use sea_orm::{ColumnTrait, Condition, EntityTrait, QueryFilter, TransactionTrait};
use uuid::Uuid;

pub async fn change(
    state: &AppState,
    actor: &SsoSession,
    target: Uuid,
    action: &str,
    session_id: Option<Uuid>,
    reason: &str,
) -> Result<(), ManagementError> {
    let reason = reason.trim();
    if reason.is_empty() || reason.chars().count() > 500 {
        return Err(ManagementError::Invalid("recovery_reason_required"));
    }
    let txn = state.db.begin().await?;
    super::admin::lock_policy(&txn).await?;
    super::admin::require_recent_super_admin(&txn, actor, &state.config.sso).await?;
    let user = super::password::PasswordIdentityService::lock_user(&txn, target).await?;
    match action {
        "revoke_one" => {
            let id = session_id.ok_or(ManagementError::Invalid("invalid_request"))?;
            if sso_sessions::Entity::find_by_id(id)
                .filter(sso_sessions::Column::UserId.eq(target))
                .one(&txn)
                .await?
                .is_none()
            {
                return Err(ManagementError::Invalid("not_found"));
            }
            super::account_security::revoke_sessions(
                &txn,
                target,
                Condition::all().add(sso_sessions::Column::Id.eq(id)),
                "admin_revoked",
            )
            .await?;
        }
        "revoke_all" => {
            super::session::SessionService::revoke_all_login_state_for_user_in_db(
                &txn,
                target,
                "admin_revoked",
            )
            .await?;
        }
        "unlock" => {
            // Persist the authorized intent before crossing the PostgreSQL/Redis boundary.
            let event = Uuid::now_v7();
            sec::execute(&txn,
                "INSERT INTO audit_events(id,actor_id,actor_username,action,target,outcome,details) SELECT $2,id,username,'admin_sessions:unlock',$3,'pending',$4 FROM users WHERE id=$1",
                vec![actor.user_id.into(),event.into(),target.to_string().into(),
                    serde_json::json!({"reason":{"before":null,"after":reason}}).into()]).await?;
            txn.commit().await?;
            let result = super::login::LoginService::new(&state.db, &state.cache)
                .unlock(target)
                .await;
            // A Redis timeout can have an unknown outcome; retain pending on any failure.
            if result.is_ok()
                && let Err(error) = sec::execute(
                    &state.db,
                    "UPDATE audit_events SET outcome='success',http_status=200 WHERE id=$1",
                    vec![event.into()],
                )
                .await
            {
                tracing::error!(%error,audit_id=%event,"Unlock completed; audit intent retained pending");
            }
            return result;
        }
        _ => return Err(ManagementError::Invalid("invalid_request")),
    }
    sec::execute(&txn,
        "INSERT INTO audit_events(actor_id,actor_username,action,target,outcome,http_status,details) SELECT id,username,$2,$3,'success',200,$4 FROM users WHERE id=$1",
        vec![actor.user_id.into(), format!("admin_sessions:{action}").into(), target.to_string().into(),
            serde_json::json!({"reason":{"before":null,"after":reason}, "session_id":{"before":null,"after":session_id}}).into()]).await?;
    sec::notify(&txn, &user, "sessions_revoked").await?;
    txn.commit().await?;
    Ok(())
}
