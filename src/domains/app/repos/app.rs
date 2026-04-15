use sqlx::postgres::PgPool;
use uuid::Uuid;

use crate::shared::error::AppError;

use super::super::models::{App, CreateAppRequest, UpdateAppRequest};

pub struct AppRepo;

impl AppRepo {
    pub async fn create(pool: &PgPool, req: &CreateAppRequest) -> Result<App, AppError> {
        let app = sqlx::query_as::<_, App>(
            "INSERT INTO apps (name, code, description) VALUES ($1, $2, $3) RETURNING *",
        )
        .bind(&req.name)
        .bind(&req.code)
        .bind(&req.description)
        .fetch_one(pool)
        .await?;
        Ok(app)
    }

    pub async fn find_by_id(pool: &PgPool, id: Uuid) -> Result<Option<App>, AppError> {
        sqlx::query_as::<_, App>("SELECT * FROM apps WHERE id = $1")
            .bind(id)
            .fetch_optional(pool)
            .await
            .map_err(Into::into)
    }

    pub async fn find_by_code(pool: &PgPool, code: &str) -> Result<Option<App>, AppError> {
        sqlx::query_as::<_, App>("SELECT * FROM apps WHERE code = $1")
            .bind(code)
            .fetch_optional(pool)
            .await
            .map_err(Into::into)
    }

    pub async fn list(
        pool: &PgPool,
        page: i64,
        page_size: i64,
    ) -> Result<(Vec<App>, i64), AppError> {
        let offset = (page - 1) * page_size;
        let apps = sqlx::query_as::<_, App>(
            "SELECT * FROM apps ORDER BY created_at DESC LIMIT $1 OFFSET $2",
        )
        .bind(page_size)
        .bind(offset)
        .fetch_all(pool)
        .await?;

        let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM apps")
            .fetch_one(pool)
            .await?;

        Ok((apps, total))
    }

    pub async fn update(
        pool: &PgPool,
        id: Uuid,
        req: &UpdateAppRequest,
    ) -> Result<App, AppError> {
        let app = Self::find_by_id(pool, id)
            .await?
            .ok_or(AppError::NotFound("app".into()))?;

        let name = req.name.as_deref().unwrap_or(&app.name);
        let description = req.description.as_deref().or(app.description.as_deref());
        let enabled = req.enabled.unwrap_or(app.enabled);

        let updated = sqlx::query_as::<_, App>(
            "UPDATE apps SET name = $1, description = $2, enabled = $3, updated_at = now() WHERE id = $4 RETURNING *",
        )
        .bind(name)
        .bind(description)
        .bind(enabled)
        .bind(id)
        .fetch_one(pool)
        .await?;
        Ok(updated)
    }

    pub async fn delete(pool: &PgPool, id: Uuid) -> Result<(), AppError> {
        let result = sqlx::query("DELETE FROM apps WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await?;
        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("app".into()));
        }
        Ok(())
    }
}
