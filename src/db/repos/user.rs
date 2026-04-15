use sqlx::postgres::PgPool;
use crate::shared::error::AppError;

#[derive(Debug, sqlx::FromRow, serde::Serialize, Clone)]
pub struct User {
    pub id: uuid::Uuid,
    pub username: String,
    pub password_hash: String,
    pub email: String,
    pub status: i16,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, serde::Serialize, Clone)]
pub struct UserDTO {
    pub id: uuid::Uuid,
    pub username: String,
    pub email: String,
    pub status: i16,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl From<User> for UserDTO {
    fn from(u: User) -> Self {
        Self {
            id: u.id,
            username: u.username,
            email: u.email,
            status: u.status,
            created_at: u.created_at,
            updated_at: u.updated_at,
        }
    }
}

#[derive(Debug, serde::Deserialize, validator::Validate)]
pub struct UpdateUser {
    #[validate(length(min = 3, max = 64))]
    pub username: Option<String>,
    #[validate(email)]
    pub email: Option<String>,
    pub status: Option<i16>,
}

#[derive(Debug, serde::Deserialize, validator::Validate)]
pub struct CreateUser {
    #[validate(length(min = 3, max = 64))]
    pub username: String,
    #[validate(email)]
    pub email: String,
    #[validate(length(min = 8))]
    pub password: String,
}

pub struct UserRepo;

impl UserRepo {
    pub async fn create(pool: &PgPool, input: &CreateUser, password_hash: &str) -> Result<User, AppError> {
        let user = sqlx::query_as::<_, User>(
            "INSERT INTO users (username, password_hash, email) VALUES ($1, $2, $3) RETURNING *"
        )
        .bind(&input.username)
        .bind(password_hash)
        .bind(&input.email)
        .fetch_one(pool)
        .await?;
        Ok(user)
    }

    pub async fn find_by_id(pool: &PgPool, id: uuid::Uuid) -> Result<Option<User>, AppError> {
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

    pub async fn list(pool: &PgPool, page: i64, page_size: i64) -> Result<(Vec<User>, i64), AppError> {
        let offset = (page - 1) * page_size;
        let users = sqlx::query_as::<_, User>(
            "SELECT * FROM users ORDER BY created_at DESC LIMIT $1 OFFSET $2"
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

    pub async fn update(pool: &PgPool, id: uuid::Uuid, input: &UpdateUser) -> Result<User, AppError> {
        let user = Self::find_by_id(pool, id)
            .await?
            .ok_or(AppError::NotFound("user".into()))?;

        let username = input.username.as_deref().unwrap_or(&user.username);
        let email = input.email.as_deref().unwrap_or(&user.email);
        let status = input.status.unwrap_or(user.status);

        let updated = sqlx::query_as::<_, User>(
            "UPDATE users SET username = $1, email = $2, status = $3, updated_at = now() WHERE id = $4 RETURNING *"
        )
        .bind(username)
        .bind(email)
        .bind(status)
        .bind(id)
        .fetch_one(pool)
        .await?;
        Ok(updated)
    }

    pub async fn delete(pool: &PgPool, id: uuid::Uuid) -> Result<(), AppError> {
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
