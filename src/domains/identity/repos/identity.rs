use super::super::models::Identity;
use crate::shared::error::AppError;
use sqlx::postgres::PgPool;
use uuid::Uuid;

pub struct IdentityRepo;

impl IdentityRepo {
    pub async fn create_password<'a, E>(
        executor: E,
        user_id: Uuid,
        password_hash: &str,
    ) -> Result<Identity, AppError>
    where
        E: sqlx::Executor<'a, Database = sqlx::Postgres>,
    {
        let identity = sqlx::query_as::<_, Identity>(
            "INSERT INTO identities (user_id, provider, credential, verified) VALUES ($1, 'password', $2, true) RETURNING *"
        )
        .bind(user_id)
        .bind(password_hash)
        .fetch_one(executor)
        .await?;
        Ok(identity)
    }

    #[allow(dead_code)] // TODO: called by bind() once OAuth provider exchange is implemented
    pub async fn create_oauth(
        pool: &PgPool,
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
        .fetch_one(pool)
        .await?;
        Ok(identity)
    }

    pub async fn find_by_user_and_provider(
        pool: &PgPool,
        user_id: Uuid,
        provider: &str,
    ) -> Result<Option<Identity>, AppError> {
        let identity = sqlx::query_as::<_, Identity>(
            "SELECT * FROM identities WHERE user_id = $1 AND provider = $2",
        )
        .bind(user_id)
        .bind(provider)
        .fetch_optional(pool)
        .await?;
        Ok(identity)
    }

    #[allow(dead_code)] // TODO: needed for OAuth login — find existing user by provider UID
    pub async fn find_by_provider(
        pool: &PgPool,
        provider: &str,
        provider_uid: &str,
    ) -> Result<Option<Identity>, AppError> {
        let identity = sqlx::query_as::<_, Identity>(
            "SELECT * FROM identities WHERE provider = $1 AND provider_uid = $2",
        )
        .bind(provider)
        .bind(provider_uid)
        .fetch_optional(pool)
        .await?;
        Ok(identity)
    }

    pub async fn list_by_user(pool: &PgPool, user_id: Uuid) -> Result<Vec<Identity>, AppError> {
        let identities = sqlx::query_as::<_, Identity>(
            "SELECT * FROM identities WHERE user_id = $1 ORDER BY created_at",
        )
        .bind(user_id)
        .fetch_all(pool)
        .await?;
        Ok(identities)
    }

    pub async fn delete(pool: &PgPool, user_id: Uuid, provider: &str) -> Result<(), AppError> {
        let result = sqlx::query("DELETE FROM identities WHERE user_id = $1 AND provider = $2")
            .bind(user_id)
            .bind(provider)
            .execute(pool)
            .await?;
        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("identity".into()));
        }
        Ok(())
    }

    pub async fn count_by_user(pool: &PgPool, user_id: Uuid) -> Result<i64, AppError> {
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM identities WHERE user_id = $1")
            .bind(user_id)
            .fetch_one(pool)
            .await?;
        Ok(count)
    }

    pub async fn update_credential<'a, E>(
        executor: E,
        user_id: Uuid,
        provider: &str,
        credential: &str,
    ) -> Result<(), AppError>
    where
        E: sqlx::Executor<'a, Database = sqlx::Postgres>,
    {
        let result = sqlx::query(
            "UPDATE identities SET credential = $1, updated_at = now() WHERE user_id = $2 AND provider = $3"
        )
        .bind(credential)
        .bind(user_id)
        .bind(provider)
        .execute(executor)
        .await?;
        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("identity".into()));
        }
        Ok(())
    }
}
