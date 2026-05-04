use std::sync::Arc;

use sqlx::postgres::PgPool;
use uuid::Uuid;

use crate::domain::federation::entity::{
    CreateSocialProviderRequest, SocialProvider, UpdateSocialProviderRequest,
};
use crate::domain::federation::repo::SocialStore;
use crate::shared::error::{AppError, require_found, require_rows_affected};

pub struct SqlxSocialStore {
    pool: Arc<PgPool>,
}

impl SqlxSocialStore {
    pub fn new(pool: Arc<PgPool>) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl SocialStore for SqlxSocialStore {
    async fn create_provider(
        &self,
        req: &CreateSocialProviderRequest,
    ) -> Result<SocialProvider, AppError> {
        let provider = sqlx::query_as::<_, SocialProvider>(
            "INSERT INTO social_providers (name, display_name, client_id, client_secret, authorize_url, token_url, userinfo_url, scopes) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *",
        )
        .bind(&req.name)
        .bind(&req.display_name)
        .bind(&req.client_id)
        .bind(&req.client_secret)
        .bind(&req.authorize_url)
        .bind(&req.token_url)
        .bind(&req.userinfo_url)
        .bind(&req.scopes)
        .fetch_one(&*self.pool)
        .await?;
        Ok(provider)
    }

    async fn find_provider_by_name(&self, name: &str) -> Result<Option<SocialProvider>, AppError> {
        sqlx::query_as::<_, SocialProvider>("SELECT * FROM social_providers WHERE name = $1")
            .bind(name)
            .fetch_optional(&*self.pool)
            .await
            .map_err(Into::into)
    }

    async fn find_provider_by_id(&self, id: Uuid) -> Result<Option<SocialProvider>, AppError> {
        sqlx::query_as::<_, SocialProvider>("SELECT * FROM social_providers WHERE id = $1")
            .bind(id)
            .fetch_optional(&*self.pool)
            .await
            .map_err(Into::into)
    }

    async fn find_enabled_provider_by_name(
        &self,
        name: &str,
    ) -> Result<Option<SocialProvider>, AppError> {
        sqlx::query_as::<_, SocialProvider>(
            "SELECT * FROM social_providers WHERE name = $1 AND enabled = true",
        )
        .bind(name)
        .fetch_optional(&*self.pool)
        .await
        .map_err(Into::into)
    }

    async fn list_enabled_providers(&self) -> Result<Vec<SocialProvider>, AppError> {
        sqlx::query_as::<_, SocialProvider>(
            "SELECT * FROM social_providers WHERE enabled = true ORDER BY name",
        )
        .fetch_all(&*self.pool)
        .await
        .map_err(Into::into)
    }

    async fn list_all_providers(&self) -> Result<Vec<SocialProvider>, AppError> {
        sqlx::query_as::<_, SocialProvider>("SELECT * FROM social_providers ORDER BY name")
            .fetch_all(&*self.pool)
            .await
            .map_err(Into::into)
    }

    async fn update_provider(
        &self,
        id: Uuid,
        req: &UpdateSocialProviderRequest,
    ) -> Result<SocialProvider, AppError> {
        let mut builder = sqlx::QueryBuilder::<sqlx::Postgres>::new(
            "UPDATE social_providers SET updated_at = now()",
        );
        req.display_name.push_column(&mut builder, "display_name");
        req.client_id.push_column(&mut builder, "client_id");
        req.client_secret.push_column(&mut builder, "client_secret");
        req.authorize_url.push_column(&mut builder, "authorize_url");
        req.token_url.push_column(&mut builder, "token_url");
        req.userinfo_url.push_column(&mut builder, "userinfo_url");
        req.scopes.push_column(&mut builder, "scopes");
        req.enabled.push_column(&mut builder, "enabled");
        builder.push(" WHERE id = ");
        builder.push_bind(id);
        builder.push(" RETURNING *");
        let result = builder
            .build_query_as::<SocialProvider>()
            .fetch_optional(&*self.pool)
            .await?;
        require_found(result, "social provider")
    }

    async fn delete_provider(&self, id: Uuid) -> Result<(), AppError> {
        let result = sqlx::query("DELETE FROM social_providers WHERE id = $1")
            .bind(id)
            .execute(&*self.pool)
            .await?;
        require_rows_affected(result, "social provider")
    }
}
