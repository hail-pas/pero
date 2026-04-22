use chrono::{TimeDelta, Utc};
use sqlx::postgres::PgPool;
use uuid::Uuid;

use crate::shared::error::AppError;

use super::super::models::AuthorizationCode;

pub struct AuthCodeRepo;

impl AuthCodeRepo {
    pub async fn create(
        pool: &PgPool,
        code: &str,
        client_id: Uuid,
        user_id: Uuid,
        redirect_uri: &str,
        scopes: &[String],
        code_challenge: Option<&str>,
        code_challenge_method: Option<&str>,
        nonce: Option<&str>,
        auth_time: i64,
        ttl_minutes: i64,
    ) -> Result<AuthorizationCode, AppError> {
        let expires_at = Utc::now() + TimeDelta::minutes(ttl_minutes);
        let ac = sqlx::query_as::<_, AuthorizationCode>(
            "INSERT INTO oauth2_authorization_codes (code, client_id, user_id, redirect_uri, scopes, code_challenge, code_challenge_method, nonce, auth_time, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING *",
        )
        .bind(code)
        .bind(client_id)
        .bind(user_id)
        .bind(redirect_uri)
        .bind(scopes)
        .bind(code_challenge)
        .bind(code_challenge_method)
        .bind(nonce)
        .bind(auth_time)
        .bind(expires_at)
        .fetch_one(pool)
        .await?;
        Ok(ac)
    }

    pub async fn find_active_for_update<'a, E>(
        executor: E,
        code: &str,
    ) -> Result<Option<AuthorizationCode>, AppError>
    where
        E: sqlx::Executor<'a, Database = sqlx::Postgres>,
    {
        sqlx::query_as::<_, AuthorizationCode>(
            "SELECT * FROM oauth2_authorization_codes WHERE code = $1 AND used = false AND expires_at > now() FOR UPDATE",
        )
        .bind(code)
        .fetch_optional(executor)
        .await
        .map_err(Into::into)
    }

    pub async fn consume<'a, E>(executor: E, code: &str) -> Result<bool, AppError>
    where
        E: sqlx::Executor<'a, Database = sqlx::Postgres>,
    {
        let result = sqlx::query(
            "UPDATE oauth2_authorization_codes SET used = true WHERE code = $1 AND used = false AND expires_at > now()",
        )
        .bind(code)
        .execute(executor)
        .await?;

        Ok(result.rows_affected() == 1)
    }
}
