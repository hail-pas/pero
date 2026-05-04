use sqlx::PgPool;
use std::time::Duration;
use tokio::time;

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
    let codes_result =
        sqlx::query("DELETE FROM oauth2_authorization_codes WHERE expires_at < now()")
            .execute(pool)
            .await?;
    let tokens_result = sqlx::query("DELETE FROM oauth2_tokens WHERE expires_at < now()")
        .execute(pool)
        .await?;
    Ok((codes_result.rows_affected(), tokens_result.rows_affected()))
}
