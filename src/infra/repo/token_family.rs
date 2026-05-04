use std::sync::Arc;

use sqlx::postgres::PgPool;
use uuid::Uuid;

use crate::domain::oauth::entity::TokenFamily;
use crate::domain::oauth::repo::TokenFamilyStore;
use crate::shared::error::AppError;

pub struct SqlxTokenFamilyStore {
    pool: Arc<PgPool>,
}

impl SqlxTokenFamilyStore {
    pub fn new(pool: Arc<PgPool>) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl TokenFamilyStore for SqlxTokenFamilyStore {
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
}
