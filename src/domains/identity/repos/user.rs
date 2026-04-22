use super::super::models::{UpdateMeRequest, UpdateUserRequest, User};
use crate::shared::error::AppError;
use crate::shared::pagination::validate_page;
use crate::shared::patch::push_optional_column;
use uuid::Uuid;

pub struct UserRepo;

impl UserRepo {
    pub async fn create<'a, E>(
        executor: E,
        username: &str,
        email: &str,
        phone: Option<&str>,
        nickname: Option<&str>,
    ) -> Result<User, AppError>
    where
        E: sqlx::Executor<'a, Database = sqlx::Postgres>,
    {
        let user = sqlx::query_as::<_, User>(
            "INSERT INTO users (username, email, phone, nickname) VALUES ($1, $2, $3, $4) RETURNING *"
        )
        .bind(username)
        .bind(email)
        .bind(phone)
        .bind(nickname)
        .fetch_one(executor)
        .await?;
        Ok(user)
    }

    pub async fn find_by_id<'a, E>(executor: E, id: Uuid) -> Result<Option<User>, AppError>
    where
        E: sqlx::Executor<'a, Database = sqlx::Postgres>,
    {
        let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1")
            .bind(id)
            .fetch_optional(executor)
            .await?;
        Ok(user)
    }

    pub async fn find_by_id_or_err<'a, E>(executor: E, id: Uuid) -> Result<User, AppError>
    where
        E: sqlx::Executor<'a, Database = sqlx::Postgres>,
    {
        Self::find_by_id(executor, id)
            .await?
            .ok_or(AppError::NotFound("user".into()))
    }

    pub async fn find_by_username<'a, E>(
        executor: E,
        username: &str,
    ) -> Result<Option<User>, AppError>
    where
        E: sqlx::Executor<'a, Database = sqlx::Postgres>,
    {
        let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE username = $1")
            .bind(username)
            .fetch_optional(executor)
            .await?;
        Ok(user)
    }

    pub async fn find_by_email<'a, E>(executor: E, email: &str) -> Result<Option<User>, AppError>
    where
        E: sqlx::Executor<'a, Database = sqlx::Postgres>,
    {
        let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE email = $1")
            .bind(email)
            .fetch_optional(executor)
            .await?;
        Ok(user)
    }

    pub async fn find_by_phone<'a, E>(executor: E, phone: &str) -> Result<Option<User>, AppError>
    where
        E: sqlx::Executor<'a, Database = sqlx::Postgres>,
    {
        let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE phone = $1")
            .bind(phone)
            .fetch_optional(executor)
            .await?;
        Ok(user)
    }

    pub async fn list(
        pool: &sqlx::PgPool,
        page: i64,
        page_size: i64,
    ) -> Result<(Vec<User>, i64), AppError> {
        let offset = validate_page(page, page_size)?;
        let users = sqlx::query_as::<_, User>(
            "SELECT * FROM users ORDER BY created_at DESC LIMIT $1 OFFSET $2",
        )
        .bind(page_size)
        .bind(offset)
        .fetch_all(pool)
        .await?;

        let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
            .fetch_one(pool)
            .await?;

        Ok((users, total))
    }

    pub async fn update<'a, E>(
        executor: E,
        id: Uuid,
        req: &UpdateUserRequest,
    ) -> Result<User, AppError>
    where
        E: sqlx::Executor<'a, Database = sqlx::Postgres>,
    {
        let mut builder =
            sqlx::QueryBuilder::<sqlx::Postgres>::new("UPDATE users SET updated_at = now()");
        push_optional_column(&mut builder, "username", &req.username);
        push_optional_column(&mut builder, "email", &req.email);
        req.phone.push_column(&mut builder, "phone");
        req.nickname.push_column(&mut builder, "nickname");
        req.avatar_url.push_column(&mut builder, "avatar_url");
        push_optional_column(&mut builder, "status", &req.status);
        builder.push(" WHERE id = ");
        builder.push_bind(id);
        builder.push(" RETURNING *");
        builder
            .build_query_as::<User>()
            .fetch_optional(executor)
            .await?
            .ok_or(AppError::NotFound("user".into()))
    }

    pub async fn update_me(
        pool: &sqlx::PgPool,
        id: Uuid,
        req: &UpdateMeRequest,
    ) -> Result<User, AppError> {
        let mut builder =
            sqlx::QueryBuilder::<sqlx::Postgres>::new("UPDATE users SET updated_at = now()");
        req.nickname.push_column(&mut builder, "nickname");
        req.avatar_url.push_column(&mut builder, "avatar_url");
        req.phone.push_column(&mut builder, "phone");
        builder.push(" WHERE id = ");
        builder.push_bind(id);
        builder.push(" RETURNING *");
        builder
            .build_query_as::<User>()
            .fetch_optional(pool)
            .await?
            .ok_or(AppError::NotFound("user".into()))
    }

    pub async fn delete(pool: &sqlx::PgPool, id: Uuid) -> Result<(), AppError> {
        let result = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await?;
        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("user".into()));
        }
        Ok(())
    }
}
