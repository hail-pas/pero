use sqlx::PgPool;
use std::time::Duration;
use tokio::time;

use crate::domain::oauth2::store::{AuthCodeRepo, RefreshTokenRepo};

pub async fn run(pool: PgPool, interval: Duration) {
    let mut ticker = time::interval(interval);
    ticker.tick().await;

    loop {
        ticker.tick().await;
        match cleanup(&pool).await {
            Ok((codes, tokens)) => {
                if codes > 0 || tokens > 0 {
                    tracing::info!(codes, tokens, "janitor: purged expired records");
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "janitor: cleanup failed");
            }
        }
    }
}

async fn cleanup(pool: &PgPool) -> Result<(u64, u64), crate::shared::error::AppError> {
    let codes = AuthCodeRepo::purge_expired(pool).await?;
    let tokens = RefreshTokenRepo::purge_expired(pool).await?;
    Ok((codes, tokens))
}
