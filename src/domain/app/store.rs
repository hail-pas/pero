use crate::domain::app::models::{App, CreateAppRequest, UpdateAppRequest};
use crate::shared::error::{AppError, require_found, require_rows_affected};
use crate::shared::pagination::{APPS, paginate};
use sqlx::postgres::PgPool;
use uuid::Uuid;

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

    pub async fn find_by_id_or_err(pool: &PgPool, id: Uuid) -> Result<App, AppError> {
        require_found(Self::find_by_id(pool, id).await?, "app")
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
        paginate(pool, APPS, page, page_size).await
    }

    pub async fn update(pool: &PgPool, id: Uuid, req: &UpdateAppRequest) -> Result<App, AppError> {
        let mut builder =
            sqlx::QueryBuilder::<sqlx::Postgres>::new("UPDATE apps SET updated_at = now()");
        req.name.push_column(&mut builder, "name");
        req.description.push_column(&mut builder, "description");
        req.enabled.push_column(&mut builder, "enabled");
        builder.push(" WHERE id = ");
        builder.push_bind(id);
        builder.push(" RETURNING *");
        let result = builder.build_query_as::<App>().fetch_optional(pool).await?;
        require_found(result, "app")
    }

    pub async fn delete(pool: &PgPool, id: Uuid) -> Result<(), AppError> {
        let result = sqlx::query("DELETE FROM apps WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await?;
        require_rows_affected(result, "app")
    }
}
