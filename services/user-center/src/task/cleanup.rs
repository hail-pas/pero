use std::time::Duration;

use sea_orm::DatabaseConnection;
use tokio::task::JoinHandle;

use crate::db::helper::cleanup::{
    clean_expired_authorization_codes, clean_expired_authorization_requests,
    clean_expired_contact_change_requests, clean_expired_external_login_requests,
    clean_expired_password_reset_tokens, clean_expired_refresh_tokens, clean_expired_sso_sessions,
};

pub fn start_cleanup_task(db: DatabaseConnection, interval_secs: u64) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
        interval.tick().await;

        tracing::info!(
            interval_secs,
            "periodic cleanup task started, first run in {interval_secs}s"
        );

        loop {
            interval.tick().await;
            tracing::debug!("running periodic cleanup");
            match run_cleanup(&db).await {
                Ok(()) => tracing::debug!("periodic cleanup completed"),
                Err(e) => tracing::error!(error = %e, "periodic cleanup error"),
            }
        }
    })
}

async fn run_cleanup(db: &DatabaseConnection) -> Result<(), sea_orm::DbErr> {
    macro_rules! do_clean {
        ($label:expr, $func:path) => {
            match $func(db).await {
                Ok(n) => {
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

    do_clean!(
        "authorization_requests",
        clean_expired_authorization_requests
    );
    do_clean!("authorization_codes", clean_expired_authorization_codes);
    do_clean!(
        "external_login_requests",
        clean_expired_external_login_requests
    );
    do_clean!("sso_sessions", clean_expired_sso_sessions);
    do_clean!("refresh_tokens", clean_expired_refresh_tokens);
    do_clean!(
        "contact_change_requests",
        clean_expired_contact_change_requests
    );
    do_clean!("password_reset_tokens", clean_expired_password_reset_tokens);

    Ok(())
}
