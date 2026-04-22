use sqlx::postgres::PgPool;
use uuid::Uuid;

use crate::shared::error::AppError;
use crate::shared::pagination::validate_page;
use crate::shared::patch::push_optional_column;

use super::super::models::{CreateClientRequest, OAuth2Client, UpdateClientRequest};

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
        Self::find_by_id(pool, id)
            .await?
            .ok_or(AppError::NotFound("oauth2 client".into()))
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
        let offset = validate_page(page, page_size)?;
        let clients = sqlx::query_as::<_, OAuth2Client>(
            "SELECT * FROM oauth2_clients ORDER BY created_at DESC LIMIT $1 OFFSET $2",
        )
        .bind(page_size)
        .bind(offset)
        .fetch_all(pool)
        .await?;

        let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM oauth2_clients")
            .fetch_one(pool)
            .await?;

        Ok((clients, total))
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
        builder
            .build_query_as::<OAuth2Client>()
            .fetch_optional(pool)
            .await?
            .ok_or(AppError::NotFound("oauth2 client".into()))
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
