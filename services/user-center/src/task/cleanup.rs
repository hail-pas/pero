use std::time::Duration;

use sea_orm::DatabaseConnection;
use tokio::task::JoinHandle;

use crate::config::RetentionConfig;
use crate::db::helper::cleanup::{
    CLEANUP_PASS_LIMIT, clean_expired_authorization_codes, clean_expired_authorization_requests,
    clean_expired_contact_change_requests, clean_expired_password_reset_tokens,
    clean_expired_refresh_tokens, clean_expired_sso_sessions,
};

pub fn start_cleanup_task(
    db: DatabaseConnection,
    interval_secs: u64,
    idle_ttl_seconds: u64,
    retention: RetentionConfig,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        tracing::info!(interval_secs, "periodic cleanup task started");

        loop {
            tracing::debug!("running periodic cleanup");
            let backlog = run_cleanup(&db, idle_ttl_seconds, retention).await;
            // Drain saturated batches without waiting for the full cleanup interval.
            // Keep a short pause to leave capacity for foreground requests.
            let delay = if backlog { 1 } else { interval_secs };
            tracing::debug!(backlog, "periodic cleanup completed");
            tokio::time::sleep(Duration::from_secs(delay)).await;
        }
    })
}

async fn run_cleanup(
    db: &DatabaseConnection,
    idle_ttl_seconds: u64,
    retention: RetentionConfig,
) -> bool {
    let mut backlog = false;
    macro_rules! do_clean {
        ($label:expr, $func:path $(, $arg:expr)*) => {
            match $func(db $(, $arg)*).await {
                Ok(n) => {
                    backlog |= n >= CLEANUP_PASS_LIMIT;
                    if n > 0 {
                        tracing::info!(table = $label, rows = n, "cleaned expired rows");
                    }
                }
                Err(e) => {
                    tracing::error!(table = $label, error = %e, "cleanup failed");
                }
            }
        };
    }

    do_clean!("authorization_codes", clean_expired_authorization_codes);
    do_clean!(
        "authorization_requests",
        clean_expired_authorization_requests
    );
    do_clean!("sso_sessions", clean_expired_sso_sessions, idle_ttl_seconds);
    do_clean!("refresh_tokens", clean_expired_refresh_tokens);
    do_clean!(
        "contact_change_requests",
        clean_expired_contact_change_requests
    );
    do_clean!("password_reset_tokens", clean_expired_password_reset_tokens);

    do_clean!(
        "notifications",
        crate::db::helper::cleanup::clean_notifications
    );
    do_clean!("enrollments", crate::db::helper::cleanup::clean_enrollments);
    do_clean!(
        "client_secrets",
        crate::db::helper::cleanup::clean_expired_client_secrets
    );
    do_clean!(
        "tenant_invitations",
        crate::db::helper::cleanup::clean_tenant_invitations
    );
    do_clean!(
        "backchannel_logout_deliveries",
        crate::db::helper::cleanup::clean_backchannel_deliveries
    );
    do_clean!(
        "account_sync_deliveries",
        crate::db::helper::cleanup::clean_account_sync_deliveries
    );
    do_clean!("user_mfa", crate::db::helper::cleanup::clean_expired_mfa);
    do_clean!(
        "login_events",
        crate::db::helper::cleanup::clean_login_events,
        retention.login_event_days
    );
    do_clean!(
        "unbound_identities",
        crate::db::helper::cleanup::clean_unbound_identities,
        retention.login_event_days
    );
    do_clean!(
        "audit_events",
        crate::db::helper::cleanup::clean_audit_events,
        retention.audit_event_days
    );
    backlog
}
