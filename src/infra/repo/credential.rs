use std::sync::Arc;

use sqlx::postgres::PgPool;
use uuid::Uuid;

use crate::domain::credential::entity::Identity;
use crate::domain::credential::repo::IdentityStore;
use crate::domain::user::error;
use crate::shared::error::AppError;

pub struct SqlxIdentityStore {
    pool: Arc<PgPool>,
}

impl SqlxIdentityStore {
    pub fn new(pool: Arc<PgPool>) -> Self {
        Self { pool }
    }
}
#[async_trait::async_trait]
impl IdentityStore for SqlxIdentityStore {
    async fn create_password(
        &self,
        user_id: Uuid,
        password_hash: &str,
    ) -> Result<Identity, AppError> {
        let identity = sqlx::query_as::<_, Identity>(
            "INSERT INTO identities (user_id, provider, provider_uid, credential, verified) VALUES ($1, 'password', $1, $2, true) RETURNING *"
        )
        .bind(user_id)
        .bind(password_hash)
        .fetch_one(&*self.pool)
        .await?;
        Ok(identity)
    }

    async fn create_social(
        &self,
        user_id: Uuid,
        provider: &str,
        provider_uid: &str,
    ) -> Result<Identity, AppError> {
        let identity = sqlx::query_as::<_, Identity>(
            "INSERT INTO identities (user_id, provider, provider_uid, verified) VALUES ($1, $2, $3, true) RETURNING *"
        )
        .bind(user_id)
        .bind(provider)
        .bind(provider_uid)
        .fetch_one(&*self.pool)
        .await?;
        Ok(identity)
    }

    async fn find_by_user_and_provider(
        &self,
        user_id: Uuid,
        provider: &str,
    ) -> Result<Option<Identity>, AppError> {
        let identity = sqlx::query_as::<_, Identity>(
            "SELECT * FROM identities WHERE user_id = $1 AND provider = $2",
        )
        .bind(user_id)
        .bind(provider)
        .fetch_optional(&*self.pool)
        .await?;
        Ok(identity)
    }

    async fn find_by_provider(
        &self,
        provider: &str,
        provider_uid: &str,
    ) -> Result<Option<Identity>, AppError> {
        let identity = sqlx::query_as::<_, Identity>(
            "SELECT * FROM identities WHERE provider = $1 AND provider_uid = $2",
        )
        .bind(provider)
        .bind(provider_uid)
        .fetch_optional(&*self.pool)
        .await?;
        Ok(identity)
    }

    async fn list_by_user(&self, user_id: Uuid) -> Result<Vec<Identity>, AppError> {
        let identities = sqlx::query_as::<_, Identity>(
            "SELECT * FROM identities WHERE user_id = $1 ORDER BY created_at",
        )
        .bind(user_id)
        .fetch_all(&*self.pool)
        .await?;
        Ok(identities)
    }

    async fn delete(&self, user_id: Uuid, provider: &str) -> Result<(), AppError> {
        let result = sqlx::query("DELETE FROM identities WHERE user_id = $1 AND provider = $2")
            .bind(user_id)
            .bind(provider)
            .execute(&*self.pool)
            .await?;
        if result.rows_affected() == 0 {
            return Err(error::identity_not_found());
        }
        Ok(())
    }

    async fn count_by_user(&self, user_id: Uuid) -> Result<i64, AppError> {
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM identities WHERE user_id = $1")
            .bind(user_id)
            .fetch_one(&*self.pool)
            .await?;
        Ok(count)
    }

    async fn update_credential(
        &self,
        user_id: Uuid,
        provider: &str,
        credential: &str,
    ) -> Result<(), AppError> {
        let result = sqlx::query(
            "UPDATE identities SET credential = $1, updated_at = now() WHERE user_id = $2 AND provider = $3"
        )
        .bind(credential)
        .bind(user_id)
        .bind(provider)
        .execute(&*self.pool)
        .await?;
        if result.rows_affected() == 0 {
            return Err(error::identity_not_found());
        }
        Ok(())
    }
}
