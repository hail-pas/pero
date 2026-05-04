use std::sync::Arc;

use chrono::{TimeDelta, Utc};
use sqlx::postgres::PgPool;
use uuid::Uuid;

use crate::domain::oauth::entity::{
    AuthorizationCode, OAuth2Client, RefreshToken, TokenFamily, UserAuthorization,
};
use crate::domain::oauth::models::{CreateClientRequest, UpdateClientRequest};
use crate::domain::oauth::repo::{
    AccessTokenParams, CreateAuthCodeParams, OAuth2ClientStore, OAuth2TokenStore, TokenSigner,
};
use crate::infra::jwt::{self, IdTokenClaims};
use crate::shared::error::{AppError, require_found, require_rows_affected};
use crate::shared::pagination::{OAUTH2_CLIENTS, paginate};
use crate::shared::utils;

pub struct SqlxOAuth2ClientStore {
    pool: Arc<PgPool>,
}

impl SqlxOAuth2ClientStore {
    pub fn new(pool: Arc<PgPool>) -> Self {
        Self { pool }
    }
}

pub struct SqlxRefreshTokenStore {
    pool: Arc<PgPool>,
}

impl SqlxRefreshTokenStore {
    pub fn new(pool: Arc<PgPool>) -> Self {
        Self { pool }
    }
}

fn token_hash(refresh_token: &str) -> String {
    utils::sha256_hex(refresh_token)
}

#[async_trait::async_trait]
impl OAuth2ClientStore for SqlxOAuth2ClientStore {
    async fn create(
        &self,
        client_id: &str,
        client_secret_hash: &str,
        req: &CreateClientRequest,
    ) -> Result<OAuth2Client, AppError> {
        let client = sqlx::query_as::<_, OAuth2Client>(
            "INSERT INTO oauth2_clients (app_id, client_id, client_secret_hash, client_name, redirect_uris, grant_types, scopes, post_logout_redirect_uris) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *",
        )
        .bind(req.app_id)
        .bind(client_id)
        .bind(client_secret_hash)
        .bind(&req.client_name)
        .bind(&req.redirect_uris)
        .bind(&req.grant_types)
        .bind(&req.scopes)
        .bind(&req.post_logout_redirect_uris)
        .fetch_one(&*self.pool)
        .await?;
        Ok(client)
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<OAuth2Client>, AppError> {
        sqlx::query_as::<_, OAuth2Client>("SELECT * FROM oauth2_clients WHERE id = $1")
            .bind(id)
            .fetch_optional(&*self.pool)
            .await
            .map_err(Into::into)
    }

    async fn find_by_client_id(&self, client_id: &str) -> Result<Option<OAuth2Client>, AppError> {
        sqlx::query_as::<_, OAuth2Client>("SELECT * FROM oauth2_clients WHERE client_id = $1")
            .bind(client_id)
            .fetch_optional(&*self.pool)
            .await
            .map_err(Into::into)
    }

    async fn list(&self, page: i64, page_size: i64) -> Result<(Vec<OAuth2Client>, i64), AppError> {
        paginate(&self.pool, OAUTH2_CLIENTS, page, page_size).await
    }

    async fn update(&self, id: Uuid, req: &UpdateClientRequest) -> Result<OAuth2Client, AppError> {
        let mut builder = sqlx::QueryBuilder::<sqlx::Postgres>::new(
            "UPDATE oauth2_clients SET updated_at = now()",
        );
        req.client_name.push_column(&mut builder, "client_name");
        req.redirect_uris.push_column(&mut builder, "redirect_uris");
        req.grant_types.push_column(&mut builder, "grant_types");
        req.scopes.push_column(&mut builder, "scopes");
        req.post_logout_redirect_uris
            .push_column(&mut builder, "post_logout_redirect_uris");
        req.enabled.push_column(&mut builder, "enabled");
        builder.push(" WHERE id = ");
        builder.push_bind(id);
        builder.push(" RETURNING *");
        let result = builder
            .build_query_as::<OAuth2Client>()
            .fetch_optional(&*self.pool)
            .await?;
        require_found(result, "oauth2 client")
    }

    async fn delete(&self, id: Uuid) -> Result<(), AppError> {
        let result = sqlx::query("DELETE FROM oauth2_clients WHERE id = $1")
            .bind(id)
            .execute(&*self.pool)
            .await?;
        require_rows_affected(result, "oauth2 client")
    }
}

#[async_trait::async_trait]
impl OAuth2TokenStore for SqlxRefreshTokenStore {
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

    async fn create_refresh_token(
        &self,
        client_id: Uuid,
        user_id: Uuid,
        refresh_token: &str,
        scopes: &[String],
        auth_time: i64,
        ttl_days: i64,
        family_id: Option<Uuid>,
    ) -> Result<RefreshToken, AppError> {
        let expires_at = Utc::now() + TimeDelta::days(ttl_days);
        let hash = token_hash(refresh_token);
        let token = sqlx::query_as::<_, RefreshToken>(
            "INSERT INTO oauth2_tokens (client_id, user_id, refresh_token, scopes, auth_time, expires_at, family_id) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *",
        )
        .bind(client_id)
        .bind(user_id)
        .bind(hash)
        .bind(scopes)
        .bind(auth_time)
        .bind(expires_at)
        .bind(family_id)
        .fetch_one(&*self.pool)
        .await?;
        Ok(token)
    }

    async fn find_active_refresh_for_update(
        &self,
        refresh_token: &str,
    ) -> Result<Option<RefreshToken>, AppError> {
        let hash = token_hash(refresh_token);
        sqlx::query_as::<_, RefreshToken>(
            "SELECT * FROM oauth2_tokens WHERE refresh_token = $1 AND revoked = false AND expires_at > now() FOR UPDATE",
        )
        .bind(hash)
        .fetch_optional(&*self.pool)
        .await
        .map_err(Into::into)
    }

    async fn revoke_refresh(&self, id: Uuid) -> Result<(), AppError> {
        sqlx::query("UPDATE oauth2_tokens SET revoked = true WHERE id = $1")
            .bind(id)
            .execute(&*self.pool)
            .await?;
        Ok(())
    }

    async fn find_revoked_by_token(
        &self,
        refresh_token: &str,
    ) -> Result<Option<RefreshToken>, AppError> {
        let hash = token_hash(refresh_token);
        sqlx::query_as::<_, RefreshToken>(
            "SELECT * FROM oauth2_tokens WHERE refresh_token = $1 AND revoked = true AND expires_at > now() - interval '30 days'",
        )
        .bind(hash)
        .fetch_optional(&*self.pool)
        .await
        .map_err(Into::into)
    }

    async fn revoke_all_for_user_client(
        &self,
        user_id: Uuid,
        client_id: Uuid,
    ) -> Result<(), AppError> {
        sqlx::query(
            "UPDATE oauth2_tokens SET revoked = true WHERE user_id = $1 AND client_id = $2",
        )
        .bind(user_id)
        .bind(client_id)
        .execute(&*self.pool)
        .await?;
        Ok(())
    }

    async fn revoke_all_for_user(&self, user_id: Uuid) -> Result<(), AppError> {
        sqlx::query("UPDATE oauth2_tokens SET revoked = true WHERE user_id = $1")
            .bind(user_id)
            .execute(&*self.pool)
            .await?;
        Ok(())
    }

    async fn list_active_by_user(&self, user_id: Uuid) -> Result<Vec<UserAuthorization>, AppError> {
        sqlx::query_as::<_, UserAuthorization>(
            r#"SELECT c.client_name, t.scopes, t.created_at, t.id as token_id
               FROM oauth2_tokens t
               JOIN oauth2_clients c ON t.client_id = c.id
               WHERE t.user_id = $1 AND t.revoked = false AND t.expires_at > now()
               ORDER BY t.created_at DESC"#,
        )
        .bind(user_id)
        .fetch_all(&*self.pool)
        .await
        .map_err(Into::into)
    }

    async fn revoke_for_user(&self, id: Uuid, user_id: Uuid) -> Result<(), AppError> {
        let result =
            sqlx::query("UPDATE oauth2_tokens SET revoked = true WHERE id = $1 AND user_id = $2")
                .bind(id)
                .bind(user_id)
                .execute(&*self.pool)
                .await?;
        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("authorization".into()));
        }
        Ok(())
    }

    async fn create_token_family(
        &self,
        client_id: Uuid,
        user_id: Uuid,
    ) -> Result<TokenFamily, AppError> {
        sqlx::query_as::<_, TokenFamily>(
            "INSERT INTO token_families (client_id, user_id) VALUES ($1, $2) RETURNING *",
        )
        .bind(client_id)
        .bind(user_id)
        .fetch_one(&*self.pool)
        .await
        .map_err(Into::into)
    }

    async fn revoke_token_family(&self, family_id: Uuid) -> Result<(), AppError> {
        sqlx::query("UPDATE token_families SET revoked = true WHERE id = $1")
            .bind(family_id)
            .execute(&*self.pool)
            .await?;
        sqlx::query("UPDATE oauth2_tokens SET revoked = true WHERE family_id = $1")
            .bind(family_id)
            .execute(&*self.pool)
            .await?;
        Ok(())
    }

    async fn exchange_auth_code(
        &self,
        code: &str,
        _client_id: Uuid,
        _user_id: Uuid,
        _scopes: &[String],
        _auth_time: i64,
        refresh_ttl_days: i64,
    ) -> Result<(AuthorizationCode, Option<String>), AppError> {
        let mut tx = self.pool.begin().await?;

        let auth_code = sqlx::query_as::<_, AuthorizationCode>(
            "SELECT * FROM oauth2_authorization_codes WHERE code = $1 AND used = false AND expires_at > now() FOR UPDATE",
        )
        .bind(code)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| crate::domain::oauth::error::OAuth2Error::InvalidAuthCode)?;

        {
            let result = sqlx::query(
                "UPDATE oauth2_authorization_codes SET used = true WHERE code = $1 AND used = false AND expires_at > now()",
            )
            .bind(code)
            .execute(&mut *tx)
            .await?;
            if result.rows_affected() != 1 {
                return Err(crate::domain::oauth::error::OAuth2Error::InvalidAuthCode.into());
            }
        }

        let family = sqlx::query_as::<_, TokenFamily>(
            "INSERT INTO token_families (client_id, user_id) VALUES ($1, $2) RETURNING *",
        )
        .bind(auth_code.client_id)
        .bind(auth_code.user_id)
        .fetch_one(&mut *tx)
        .await?;

        let rt = utils::random_hex_token();
        let expires_at = Utc::now() + TimeDelta::days(refresh_ttl_days);
        let hash = token_hash(&rt);
        sqlx::query_as::<_, RefreshToken>(
            "INSERT INTO oauth2_tokens (client_id, user_id, refresh_token, scopes, auth_time, expires_at, family_id) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *",
        )
        .bind(auth_code.client_id)
        .bind(auth_code.user_id)
        .bind(hash)
        .bind(&auth_code.scopes)
        .bind(auth_code.auth_time)
        .bind(expires_at)
        .bind(family.id)
        .fetch_one(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok((auth_code, Some(rt)))
    }

    async fn rotate_refresh_token(
        &self,
        old_token: &str,
        client_id: Uuid,
        user_id: Uuid,
        scopes: &[String],
        auth_time: i64,
        ttl_days: i64,
        family_id: Option<Uuid>,
    ) -> Result<(RefreshToken, Option<String>), AppError> {
        let mut tx = self.pool.begin().await?;

        let old_hash = token_hash(old_token);
        let stored = sqlx::query_as::<_, RefreshToken>(
            "SELECT * FROM oauth2_tokens WHERE refresh_token = $1 AND revoked = false AND expires_at > now() FOR UPDATE",
        )
        .bind(old_hash)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| crate::domain::oauth::error::OAuth2Error::InvalidRefreshToken)?;

        sqlx::query("UPDATE oauth2_tokens SET revoked = true WHERE id = $1")
            .bind(stored.id)
            .execute(&mut *tx)
            .await?;

        let rt = utils::random_hex_token();
        let expires_at = Utc::now() + TimeDelta::days(ttl_days);
        let new_hash = token_hash(&rt);
        let new_token = sqlx::query_as::<_, RefreshToken>(
            "INSERT INTO oauth2_tokens (client_id, user_id, refresh_token, scopes, auth_time, expires_at, family_id) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *",
        )
        .bind(client_id)
        .bind(user_id)
        .bind(new_hash)
        .bind(scopes)
        .bind(auth_time)
        .bind(expires_at)
        .bind(family_id)
        .fetch_one(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok((new_token, Some(rt)))
    }

    async fn revoke_token_if_owned(&self, token: &str, client_id: Uuid) -> Result<(), AppError> {
        let mut tx = self.pool.begin().await?;
        let hash = token_hash(token);
        if let Some(stored) = sqlx::query_as::<_, RefreshToken>(
            "SELECT * FROM oauth2_tokens WHERE refresh_token = $1 AND revoked = false AND expires_at > now() FOR UPDATE",
        )
        .bind(hash)
        .fetch_optional(&mut *tx)
        .await?
        {
            if stored.client_id == client_id {
                sqlx::query("UPDATE oauth2_tokens SET revoked = true WHERE id = $1")
                    .bind(stored.id)
                    .execute(&mut *tx)
                    .await?;
            }
        }
        tx.commit().await?;
        Ok(())
    }

    async fn purge_expired_tokens(&self) -> Result<u64, AppError> {
        let result = sqlx::query("DELETE FROM oauth2_tokens WHERE expires_at < now()")
            .execute(&*self.pool)
            .await?;
        Ok(result.rows_affected())
    }

    async fn purge_expired_auth_codes(&self) -> Result<u64, AppError> {
        let result = sqlx::query("DELETE FROM oauth2_authorization_codes WHERE expires_at < now()")
            .execute(&*self.pool)
            .await?;
        Ok(result.rows_affected())
    }
}

pub struct JwtTokenSigner {
    keys: Arc<crate::infra::jwt::JwtKeys>,
    access_token_ttl_minutes: i64,
    issuer: String,
}

impl JwtTokenSigner {
    pub fn new(
        keys: Arc<crate::infra::jwt::JwtKeys>,
        access_token_ttl_minutes: i64,
        issuer: String,
    ) -> Self {
        Self {
            keys,
            access_token_ttl_minutes,
            issuer,
        }
    }
}

impl TokenSigner for JwtTokenSigner {
    fn sign_access_token(&self, params: AccessTokenParams) -> Result<String, AppError> {
        jwt::sign_access_token(
            &params.sub,
            params.roles,
            &self.keys,
            self.access_token_ttl_minutes,
            params.scope,
            params.azp,
            params.app_id,
            params.sid,
        )
    }

    fn sign_id_token(
        &self,
        sub: String,
        iss: String,
        aud: String,
        exp: i64,
        iat: i64,
        auth_time: i64,
        nonce: Option<String>,
        name: Option<String>,
        nickname: Option<String>,
        picture: Option<String>,
        email: Option<String>,
        email_verified: Option<bool>,
        phone_number: Option<String>,
        phone_number_verified: Option<bool>,
        sid: Option<String>,
    ) -> Result<String, AppError> {
        let claims = IdTokenClaims {
            sub,
            iss,
            aud,
            exp,
            iat,
            auth_time,
            nonce,
            name,
            nickname,
            picture,
            email,
            email_verified,
            phone_number,
            phone_number_verified,
            sid,
        };
        jwt::sign_id_token(&claims, &self.keys)
    }

    fn issuer(&self) -> &str {
        &self.issuer
    }
}
