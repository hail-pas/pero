use chrono::{TimeDelta, Utc};
use sqlx::postgres::PgPool;
use uuid::Uuid;

use crate::domain::oauth2::models::{
    AuthorizationCode, CreateClientRequest, OAuth2Client, RefreshToken, UpdateClientRequest,
};
use crate::shared::error::{AppError, require_found};
use crate::shared::pagination::{paginate, OAUTH2_CLIENTS};
use crate::shared::patch::push_optional_column;

pub struct OAuth2ClientRepo;

impl OAuth2ClientRepo {
    pub async fn create(
        pool: &PgPool,
        client_id: &str,
        client_secret_hash: &str,
        req: &CreateClientRequest,
    ) -> Result<OAuth2Client, AppError> {
        let client = sqlx::query_as::<_, OAuth2Client>(
            "INSERT INTO oauth2_clients (app_id, client_id, client_secret_hash, client_name, redirect_uris, grant_types, scopes) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *",
        )
        .bind(req.app_id)
        .bind(client_id)
        .bind(client_secret_hash)
        .bind(&req.client_name)
        .bind(&req.redirect_uris)
        .bind(&req.grant_types)
        .bind(&req.scopes)
        .fetch_one(pool)
        .await?;
        Ok(client)
    }

    pub async fn find_by_id(pool: &PgPool, id: Uuid) -> Result<Option<OAuth2Client>, AppError> {
        sqlx::query_as::<_, OAuth2Client>("SELECT * FROM oauth2_clients WHERE id = $1")
            .bind(id)
            .fetch_optional(pool)
            .await
            .map_err(Into::into)
    }

    pub async fn find_by_id_or_err(pool: &PgPool, id: Uuid) -> Result<OAuth2Client, AppError> {
        require_found(Self::find_by_id(pool, id).await?, "oauth2 client")
    }

    pub async fn find_by_client_id(
        pool: &PgPool,
        client_id: &str,
    ) -> Result<Option<OAuth2Client>, AppError> {
        sqlx::query_as::<_, OAuth2Client>("SELECT * FROM oauth2_clients WHERE client_id = $1")
            .bind(client_id)
            .fetch_optional(pool)
            .await
            .map_err(Into::into)
    }

    pub async fn list(
        pool: &PgPool,
        page: i64,
        page_size: i64,
    ) -> Result<(Vec<OAuth2Client>, i64), AppError> {
        paginate(pool, OAUTH2_CLIENTS, page, page_size).await
    }

    pub async fn update(
        pool: &PgPool,
        id: Uuid,
        req: &UpdateClientRequest,
    ) -> Result<OAuth2Client, AppError> {
        let mut builder = sqlx::QueryBuilder::<sqlx::Postgres>::new(
            "UPDATE oauth2_clients SET updated_at = now()",
        );
        push_optional_column(&mut builder, "client_name", &req.client_name);
        push_optional_column(&mut builder, "redirect_uris", &req.redirect_uris);
        push_optional_column(&mut builder, "scopes", &req.scopes);
        push_optional_column(&mut builder, "enabled", &req.enabled);
        builder.push(" WHERE id = ");
        builder.push_bind(id);
        builder.push(" RETURNING *");
        let result = builder
            .build_query_as::<OAuth2Client>()
            .fetch_optional(pool)
            .await?;
        require_found(result, "oauth2 client")
    }

    pub async fn delete(pool: &PgPool, id: Uuid) -> Result<(), AppError> {
        let result = sqlx::query("DELETE FROM oauth2_clients WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await?;
        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("oauth2 client".into()));
        }
        Ok(())
    }
}

pub struct RefreshTokenRepo;

impl RefreshTokenRepo {
    fn token_hash(refresh_token: &str) -> String {
        crate::shared::utils::sha256_hex(refresh_token)
    }

    pub async fn create<'a, E>(
        executor: E,
        client_id: Uuid,
        user_id: Uuid,
        refresh_token: &str,
        scopes: &[String],
        auth_time: i64,
        ttl_days: i64,
    ) -> Result<RefreshToken, AppError>
    where
        E: sqlx::Executor<'a, Database = sqlx::Postgres>,
    {
        let expires_at = Utc::now() + TimeDelta::days(ttl_days);
        let token_hash = Self::token_hash(refresh_token);
        let token = sqlx::query_as::<_, RefreshToken>(
            "INSERT INTO oauth2_tokens (client_id, user_id, refresh_token, scopes, auth_time, expires_at) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *",
        )
        .bind(client_id)
        .bind(user_id)
        .bind(token_hash)
        .bind(scopes)
        .bind(auth_time)
        .bind(expires_at)
        .fetch_one(executor)
        .await?;
        Ok(token)
    }

    pub async fn find_active_for_update<'a, E>(
        executor: E,
        refresh_token: &str,
    ) -> Result<Option<RefreshToken>, AppError>
    where
        E: sqlx::Executor<'a, Database = sqlx::Postgres>,
    {
        let token_hash = Self::token_hash(refresh_token);
        sqlx::query_as::<_, RefreshToken>(
            "SELECT * FROM oauth2_tokens WHERE refresh_token = $1 AND revoked = false AND expires_at > now() FOR UPDATE",
        )
        .bind(token_hash)
        .fetch_optional(executor)
        .await
        .map_err(Into::into)
    }

    pub async fn revoke<'a, E>(executor: E, id: Uuid) -> Result<(), AppError>
    where
        E: sqlx::Executor<'a, Database = sqlx::Postgres>,
    {
        sqlx::query("UPDATE oauth2_tokens SET revoked = true WHERE id = $1")
            .bind(id)
            .execute(executor)
            .await?;
        Ok(())
    }

    pub async fn find_revoked_by_token(
        pool: &PgPool,
        refresh_token: &str,
    ) -> Result<Option<RefreshToken>, AppError> {
        let token_hash = Self::token_hash(refresh_token);
        sqlx::query_as::<_, RefreshToken>(
            "SELECT * FROM oauth2_tokens WHERE refresh_token = $1 AND revoked = true AND expires_at > now() - interval '30 days'",
        )
        .bind(token_hash)
        .fetch_optional(pool)
        .await
        .map_err(Into::into)
    }

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

    pub async fn revoke_all_for_user(pool: &PgPool, user_id: Uuid) -> Result<(), AppError> {
        sqlx::query("UPDATE oauth2_tokens SET revoked = true WHERE user_id = $1")
            .bind(user_id)
            .execute(pool)
            .await?;
        Ok(())
    }

    pub async fn purge_expired(pool: &PgPool) -> Result<u64, AppError> {
        let result = sqlx::query(
            "DELETE FROM oauth2_tokens WHERE expires_at < now()",
        )
        .execute(pool)
        .await?;
        Ok(result.rows_affected())
    }
}

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

    pub async fn purge_expired(pool: &PgPool) -> Result<u64, AppError> {
        let result = sqlx::query(
            "DELETE FROM oauth2_authorization_codes WHERE expires_at < now()",
        )
        .execute(pool)
        .await?;
        Ok(result.rows_affected())
    }
}
