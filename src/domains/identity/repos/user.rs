use super::super::models::User;
use crate::shared::error::AppError;
use sqlx::postgres::PgPool;
use uuid::Uuid;

pub struct UserRepo;

impl UserRepo {
    pub async fn create(
        pool: &PgPool,
        username: &str,
        email: &str,
        phone: Option<&str>,
        nickname: Option<&str>,
        password_hash: Option<&str>,
    ) -> Result<User, AppError> {
        let user = sqlx::query_as::<_, User>(
            "INSERT INTO users (username, email, phone, nickname, password_hash) VALUES ($1, $2, $3, $4, $5) RETURNING *"
        )
        .bind(username)
        .bind(email)
        .bind(phone)
        .bind(nickname)
        .bind(password_hash)
        .fetch_one(pool)
        .await?;
        Ok(user)
    }

    pub async fn find_by_id(pool: &PgPool, id: Uuid) -> Result<Option<User>, AppError> {
        let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE id = $1")
            .bind(id)
            .fetch_optional(pool)
            .await?;
        Ok(user)
    }

    pub async fn find_by_username(pool: &PgPool, username: &str) -> Result<Option<User>, AppError> {
        let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE username = $1")
            .bind(username)
            .fetch_optional(pool)
            .await?;
        Ok(user)
    }

    pub async fn find_by_email(pool: &PgPool, email: &str) -> Result<Option<User>, AppError> {
        let user = sqlx::query_as::<_, User>("SELECT * FROM users WHERE email = $1")
            .bind(email)
            .fetch_optional(pool)
            .await?;
        Ok(user)
    }

    pub async fn list(
        pool: &PgPool,
        page: i64,
        page_size: i64,
    ) -> Result<(Vec<User>, i64), AppError> {
        let offset = (page - 1) * page_size;
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

    pub async fn update(
        pool: &PgPool,
        id: Uuid,
        username: Option<&str>,
        email: Option<&str>,
        phone: Option<&str>,
        nickname: Option<&str>,
        avatar_url: Option<&str>,
        status: Option<i16>,
    ) -> Result<User, AppError> {
        let user = Self::find_by_id(pool, id)
            .await?
            .ok_or(AppError::NotFound("user".into()))?;

        let username = username.unwrap_or(&user.username);
        let email = email.unwrap_or(&user.email);
        let phone = phone.or(user.phone.as_deref());
        let nickname = nickname.or(user.nickname.as_deref());
        let avatar_url = avatar_url.or(user.avatar_url.as_deref());
        let status = status.unwrap_or(user.status);

        let updated = sqlx::query_as::<_, User>(
            "UPDATE users SET username = $1, email = $2, phone = $3, nickname = $4, avatar_url = $5, status = $6, updated_at = now() WHERE id = $7 RETURNING *"
        )
        .bind(username)
        .bind(email)
        .bind(phone)
        .bind(nickname)
        .bind(avatar_url)
        .bind(status)
        .bind(id)
        .fetch_one(pool)
        .await?;
        Ok(updated)
    }

    pub async fn update_me(
        pool: &PgPool,
        id: Uuid,
        nickname: Option<&str>,
        avatar_url: Option<&str>,
        phone: Option<&str>,
    ) -> Result<User, AppError> {
        let user = Self::find_by_id(pool, id)
            .await?
            .ok_or(AppError::NotFound("user".into()))?;

        let nickname = nickname.or(user.nickname.as_deref());
        let avatar_url = avatar_url.or(user.avatar_url.as_deref());
        let phone = phone.or(user.phone.as_deref());

        let updated = sqlx::query_as::<_, User>(
            "UPDATE users SET nickname = $1, avatar_url = $2, phone = $3, updated_at = now() WHERE id = $4 RETURNING *"
        )
        .bind(nickname)
        .bind(avatar_url)
        .bind(phone)
        .bind(id)
        .fetch_one(pool)
        .await?;
        Ok(updated)
    }

    pub async fn delete(pool: &PgPool, id: Uuid) -> Result<(), AppError> {
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
