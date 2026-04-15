use chrono::{TimeDelta, Utc};
use sqlx::postgres::PgPool;
use uuid::Uuid;

use crate::shared::error::AppError;

use super::super::models::RefreshToken;

pub struct RefreshTokenRepo;

impl RefreshTokenRepo {
    pub async fn create(
        pool: &PgPool,
        client_id: Uuid,
        user_id: Uuid,
        refresh_token: &str,
        scopes: &[String],
        ttl_days: i64,
    ) -> Result<RefreshToken, AppError> {
        let expires_at = Utc::now() + TimeDelta::days(ttl_days);
        let token = sqlx::query_as::<_, RefreshToken>(
            "INSERT INTO oauth2_tokens (client_id, user_id, refresh_token, scopes, expires_at) VALUES ($1, $2, $3, $4, $5) RETURNING *",
        )
        .bind(client_id)
        .bind(user_id)
        .bind(refresh_token)
        .bind(scopes)
        .bind(expires_at)
        .fetch_one(pool)
        .await?;
        Ok(token)
    }

    pub async fn find_by_token(
        pool: &PgPool,
        refresh_token: &str,
    ) -> Result<Option<RefreshToken>, AppError> {
        sqlx::query_as::<_, RefreshToken>(
            "SELECT * FROM oauth2_tokens WHERE refresh_token = $1 AND revoked = false AND expires_at > now()",
        )
        .bind(refresh_token)
        .fetch_optional(pool)
        .await
        .map_err(Into::into)
    }

    pub async fn revoke(pool: &PgPool, id: Uuid) -> Result<(), AppError> {
        sqlx::query("UPDATE oauth2_tokens SET revoked = true WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await?;
        Ok(())
    }

    #[allow(dead_code)]
    pub async fn revoke_all_for_user_client(
        pool: &PgPool,
        user_id: Uuid,
        client_id: Uuid,
    ) -> Result<(), AppError> {
        sqlx::query(
            "UPDATE oauth2_tokens SET revoked = true WHERE user_id = $1 AND client_id = $2",
        )
        .bind(user_id)
        .bind(client_id)
        .execute(pool)
        .await?;
        Ok(())
    }
}
