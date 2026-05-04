use std::sync::Arc;

use sqlx::postgres::PgPool;
use uuid::Uuid;

use crate::domain::oauth::entity::OAuth2Client;
use crate::domain::oauth::models::{CreateClientRequest, UpdateClientRequest};
use crate::domain::oauth::repo::{AccessTokenParams, OAuth2ClientStore, TokenSigner};
use crate::infra::jwt::{self, IdTokenClaims};
use crate::shared::error::{AppError, require_found, require_rows_affected};
use crate::shared::pagination::{OAUTH2_CLIENTS, paginate};

pub struct SqlxOAuth2ClientStore {
    pool: Arc<PgPool>,
}

impl SqlxOAuth2ClientStore {
    pub fn new(pool: Arc<PgPool>) -> Self {
        Self { pool }
    }
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
