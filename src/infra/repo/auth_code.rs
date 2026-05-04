use std::sync::Arc;

use chrono::{TimeDelta, Utc};
use sqlx::postgres::PgPool;

use crate::domain::oauth::entity::AuthorizationCode;
use crate::domain::oauth::repo::{AuthorizationCodeStore, CreateAuthCodeParams};
use crate::shared::error::AppError;

pub struct SqlxAuthCodeStore {
    pool: Arc<PgPool>,
}

impl SqlxAuthCodeStore {
    pub fn new(pool: Arc<PgPool>) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl AuthorizationCodeStore for SqlxAuthCodeStore {
    async fn create_auth_code(
        &self,
        params: CreateAuthCodeParams,
    ) -> Result<AuthorizationCode, AppError> {
        let expires_at = Utc::now() + TimeDelta::minutes(params.ttl_minutes);
        let ac = sqlx::query_as::<_, AuthorizationCode>(
            "INSERT INTO oauth2_authorization_codes (code, client_id, user_id, redirect_uri, scopes, code_challenge, code_challenge_method, nonce, sid, auth_time, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING *",
        )
        .bind(params.code)
        .bind(params.client_id)
        .bind(params.user_id)
        .bind(params.redirect_uri)
        .bind(params.scopes)
        .bind(params.code_challenge)
        .bind(params.code_challenge_method)
        .bind(params.nonce)
        .bind(params.sid)
        .bind(params.auth_time)
        .bind(expires_at)
        .fetch_one(&*self.pool)
        .await?;
        Ok(ac)
    }

    async fn find_active_auth_code(
        &self,
        code: &str,
    ) -> Result<Option<AuthorizationCode>, AppError> {
        sqlx::query_as::<_, AuthorizationCode>(
            "SELECT * FROM oauth2_authorization_codes WHERE code = $1 AND used = false AND expires_at > now()",
        )
        .bind(code)
        .fetch_optional(&*self.pool)
        .await
        .map_err(Into::into)
    }

    async fn consume_auth_code(&self, code: &str) -> Result<bool, AppError> {
        let result = sqlx::query(
            "UPDATE oauth2_authorization_codes SET used = true WHERE code = $1 AND used = false AND expires_at > now()",
        )
        .bind(code)
        .execute(&*self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    async fn purge_expired_auth_codes(&self) -> Result<u64, AppError> {
        let result =
            sqlx::query("DELETE FROM oauth2_authorization_codes WHERE expires_at < now()")
                .execute(&*self.pool)
                .await?;
        Ok(result.rows_affected())
    }
}
