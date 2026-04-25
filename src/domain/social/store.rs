use sqlx::PgPool;
use uuid::Uuid;

use crate::domain::social::entity::{
    CreateSocialProviderRequest, SocialProvider, UpdateSocialProviderRequest,
};
use crate::shared::error::{AppError, require_found, require_rows_affected};

pub struct SocialProviderRepo;

impl SocialProviderRepo {
    pub async fn create(
        pool: &PgPool,
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
        .fetch_one(pool)
        .await?;
        Ok(provider)
    }

    pub async fn find_by_name(
        pool: &PgPool,
        name: &str,
    ) -> Result<Option<SocialProvider>, AppError> {
        sqlx::query_as::<_, SocialProvider>("SELECT * FROM social_providers WHERE name = $1")
            .bind(name)
            .fetch_optional(pool)
            .await
            .map_err(Into::into)
    }

    pub async fn find_by_id(pool: &PgPool, id: Uuid) -> Result<Option<SocialProvider>, AppError> {
        sqlx::query_as::<_, SocialProvider>("SELECT * FROM social_providers WHERE id = $1")
            .bind(id)
            .fetch_optional(pool)
            .await
            .map_err(Into::into)
    }

    pub async fn find_enabled_by_name(
        pool: &PgPool,
        name: &str,
    ) -> Result<Option<SocialProvider>, AppError> {
        sqlx::query_as::<_, SocialProvider>(
            "SELECT * FROM social_providers WHERE name = $1 AND enabled = true",
        )
        .bind(name)
        .fetch_optional(pool)
        .await
        .map_err(Into::into)
    }

    pub async fn list_enabled(pool: &PgPool) -> Result<Vec<SocialProvider>, AppError> {
        sqlx::query_as::<_, SocialProvider>(
            "SELECT * FROM social_providers WHERE enabled = true ORDER BY name",
        )
        .fetch_all(pool)
        .await
        .map_err(Into::into)
    }

    pub async fn list_all(pool: &PgPool) -> Result<Vec<SocialProvider>, AppError> {
        sqlx::query_as::<_, SocialProvider>("SELECT * FROM social_providers ORDER BY name")
            .fetch_all(pool)
            .await
            .map_err(Into::into)
    }

    pub async fn update(
        pool: &PgPool,
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
            .fetch_optional(pool)
            .await?;
        require_found(result, "social provider")
    }

    pub async fn delete(pool: &PgPool, id: Uuid) -> Result<(), AppError> {
        let result = sqlx::query("DELETE FROM social_providers WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await?;
        require_rows_affected(result, "social provider")
    }
}
