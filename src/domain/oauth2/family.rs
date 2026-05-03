use crate::shared::error::AppError;
use chrono::{DateTime, Utc};
use sqlx::postgres::PgPool;
use uuid::Uuid;

#[derive(Debug, sqlx::FromRow)]
pub struct TokenFamily {
    pub id: Uuid,
    pub client_id: Uuid,
    pub user_id: Uuid,
    pub revoked: bool,
    pub created_at: DateTime<Utc>,
}

pub struct TokenFamilyRepo;

impl TokenFamilyRepo {
    pub async fn create<'a, E>(
        executor: E,
        client_id: Uuid,
        user_id: Uuid,
    ) -> Result<TokenFamily, AppError>
    where
        E: sqlx::Executor<'a, Database = sqlx::Postgres>,
    {
        sqlx::query_as::<_, TokenFamily>(
            "INSERT INTO token_families (client_id, user_id) VALUES ($1, $2) RETURNING *",
        )
        .bind(client_id)
        .bind(user_id)
        .fetch_one(executor)
        .await
        .map_err(Into::into)
    }

    pub async fn revoke_family(pool: &PgPool, family_id: Uuid) -> Result<(), AppError> {
        sqlx::query("UPDATE token_families SET revoked = true WHERE id = $1")
            .bind(family_id)
            .execute(pool)
            .await?;
        sqlx::query("UPDATE oauth2_tokens SET revoked = true WHERE family_id = $1")
            .bind(family_id)
            .execute(pool)
            .await?;
        Ok(())
    }
}
