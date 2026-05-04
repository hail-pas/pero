use std::sync::Arc;

use sqlx::postgres::PgPool;
use uuid::Uuid;

use crate::domain::app::models::{App, CreateAppRequest, UpdateAppRequest};
use crate::domain::app::repo::AppStore;
use crate::shared::error::{AppError, require_found, require_rows_affected};
use crate::shared::pagination::{APPS, paginate};

pub struct SqlxAppStore {
    pool: Arc<PgPool>,
}

impl SqlxAppStore {
    pub fn new(pool: Arc<PgPool>) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl AppStore for SqlxAppStore {
    async fn create(&self, req: &CreateAppRequest) -> Result<App, AppError> {
        let app = sqlx::query_as::<_, App>(
            "INSERT INTO apps (name, code, description) VALUES ($1, $2, $3) RETURNING *",
        )
        .bind(&req.name)
        .bind(&req.code)
        .bind(&req.description)
        .fetch_one(&*self.pool)
        .await?;
        Ok(app)
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<App>, AppError> {
        sqlx::query_as::<_, App>("SELECT * FROM apps WHERE id = $1")
            .bind(id)
            .fetch_optional(&*self.pool)
            .await
            .map_err(Into::into)
    }

    async fn find_by_code(&self, code: &str) -> Result<Option<App>, AppError> {
        sqlx::query_as::<_, App>("SELECT * FROM apps WHERE code = $1")
            .bind(code)
            .fetch_optional(&*self.pool)
            .await
            .map_err(Into::into)
    }

    async fn list(&self, page: i64, page_size: i64) -> Result<(Vec<App>, i64), AppError> {
        paginate(&self.pool, APPS, page, page_size).await
    }

    async fn update(&self, id: Uuid, req: &UpdateAppRequest) -> Result<App, AppError> {
        let mut builder =
            sqlx::QueryBuilder::<sqlx::Postgres>::new("UPDATE apps SET updated_at = now()");
        req.name.push_column(&mut builder, "name");
        req.description.push_column(&mut builder, "description");
        req.enabled.push_column(&mut builder, "enabled");
        builder.push(" WHERE id = ");
        builder.push_bind(id);
        builder.push(" RETURNING *");
        let result = builder
            .build_query_as::<App>()
            .fetch_optional(&*self.pool)
            .await?;
        require_found(result, "app")
    }

    async fn delete(&self, id: Uuid) -> Result<(), AppError> {
        let result = sqlx::query("DELETE FROM apps WHERE id = $1")
            .bind(id)
            .execute(&*self.pool)
            .await?;
        require_rows_affected(result, "app")
    }
}
