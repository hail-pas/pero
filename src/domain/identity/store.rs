use crate::domain::identity::error;
use crate::domain::identity::models::{Identity, UpdateMeRequest, UpdateUserRequest, User};
use crate::shared::error::{AppError, require_found};
use crate::shared::pagination::{USERS, paginate};
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgPool;
use utoipa::ToSchema;
use uuid::Uuid;
use validator::Validate;

#[derive(Debug, sqlx::FromRow, Serialize, ToSchema)]
pub struct UserAttribute {
    pub id: Uuid,
    pub user_id: Uuid,
    pub key: String,
    pub value: String,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct SetAttributes {
    #[validate(length(min = 1))]
    pub attributes: Vec<AttributeItem>,
}

#[derive(Debug, Deserialize, Serialize, Validate, ToSchema)]
pub struct AttributeItem {
    #[validate(length(min = 1, max = 128))]
    pub key: String,
    #[validate(length(min = 1, max = 1024))]
    pub value: String,
}

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
        require_found(Self::find_by_id(executor, id).await?, "user")
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
        paginate(pool, USERS, page, page_size).await
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
        req.username.push_column(&mut builder, "username");
        req.email.push_column(&mut builder, "email");
        req.phone.push_column(&mut builder, "phone");
        req.nickname.push_column(&mut builder, "nickname");
        req.avatar_url.push_column(&mut builder, "avatar_url");
        req.status.push_column(&mut builder, "status");
        builder.push(" WHERE id = ");
        builder.push_bind(id);
        builder.push(" RETURNING *");
        let result = builder
            .build_query_as::<User>()
            .fetch_optional(executor)
            .await?;
        require_found(result, "user")
    }

    pub async fn update_me(
        pool: &sqlx::PgPool,
        id: Uuid,
        req: &UpdateMeRequest,
    ) -> Result<User, AppError> {
        let mut builder =
            sqlx::QueryBuilder::<sqlx::Postgres>::new("UPDATE users SET updated_at = now()");
        if req.email.as_set().is_some() {
            builder.push(", email_verified = false");
        }
        if req.phone.as_set().is_some() || matches!(req.phone, crate::shared::patch::Patch::Null) {
            builder.push(", phone_verified = false");
        }
        req.email.push_column(&mut builder, "email");
        req.nickname.push_column(&mut builder, "nickname");
        req.avatar_url.push_column(&mut builder, "avatar_url");
        req.phone.push_column(&mut builder, "phone");
        builder.push(" WHERE id = ");
        builder.push_bind(id);
        builder.push(" RETURNING *");
        let result = builder
            .build_query_as::<User>()
            .fetch_optional(pool)
            .await?;
        require_found(result, "user")
    }

    pub async fn delete(pool: &sqlx::PgPool, id: Uuid) -> Result<(), AppError> {
        let result = sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await?;
        if result.rows_affected() == 0 {
            return Err(error::user_not_found());
        }
        Ok(())
    }

    pub async fn set_email_verified(pool: &PgPool, user_id: Uuid) -> Result<(), AppError> {
        let result =
            sqlx::query("UPDATE users SET email_verified = true, updated_at = now() WHERE id = $1")
                .bind(user_id)
                .execute(pool)
                .await?;
        if result.rows_affected() == 0 {
            return Err(error::user_not_found());
        }
        Ok(())
    }

    pub async fn set_phone_verified(pool: &PgPool, user_id: Uuid) -> Result<(), AppError> {
        let result =
            sqlx::query("UPDATE users SET phone_verified = true, updated_at = now() WHERE id = $1")
                .bind(user_id)
                .execute(pool)
                .await?;
        if result.rows_affected() == 0 {
            return Err(error::user_not_found());
        }
        Ok(())
    }

    pub async fn update_password_by_identity(
        pool: &PgPool,
        user_id: Uuid,
        new_password_hash: &str,
    ) -> Result<(), AppError> {
        let result = sqlx::query(
            "UPDATE identities SET credential = $1, updated_at = now() WHERE user_id = $2 AND provider = 'password'",
        )
        .bind(new_password_hash)
        .bind(user_id)
        .execute(pool)
        .await?;
        if result.rows_affected() == 0 {
            return Err(error::identity_not_found());
        }
        Ok(())
    }
}

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
            "INSERT INTO identities (user_id, provider, provider_uid, credential, verified) VALUES ($1, 'password', $1, $2, true) RETURNING *"
        )
        .bind(user_id)
        .bind(password_hash)
        .fetch_one(executor)
        .await?;
        Ok(identity)
    }

    #[allow(dead_code)]
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

    #[allow(dead_code)]
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
            return Err(error::identity_not_found());
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
            return Err(error::identity_not_found());
        }
        Ok(())
    }
}

pub struct UserAttributeRepo;

impl UserAttributeRepo {
    pub async fn list_by_user(
        pool: &PgPool,
        user_id: Uuid,
    ) -> Result<Vec<UserAttribute>, AppError> {
        let attrs = sqlx::query_as::<_, UserAttribute>(
            "SELECT * FROM user_attributes WHERE user_id = $1 ORDER BY key",
        )
        .bind(user_id)
        .fetch_all(pool)
        .await?;
        Ok(attrs)
    }

    pub async fn upsert(
        pool: &PgPool,
        user_id: Uuid,
        items: &[AttributeItem],
    ) -> Result<(), AppError> {
        if items.is_empty() {
            return Ok(());
        }
        let keys: Vec<&str> = items.iter().map(|i| i.key.as_str()).collect();
        let values: Vec<&str> = items.iter().map(|i| i.value.as_str()).collect();
        sqlx::query(
            "INSERT INTO user_attributes (user_id, key, value)
             SELECT $1, k, v FROM UNNEST($2::text[], $3::text[]) AS t(k, v)
             ON CONFLICT (user_id, key) DO UPDATE SET value = EXCLUDED.value",
        )
        .bind(user_id)
        .bind(&keys)
        .bind(&values)
        .execute(pool)
        .await?;
        Ok(())
    }

    pub async fn delete_by_user(pool: &PgPool, user_id: Uuid, key: &str) -> Result<(), AppError> {
        sqlx::query("DELETE FROM user_attributes WHERE user_id = $1 AND key = $2")
            .bind(user_id)
            .bind(key)
            .execute(pool)
            .await?;
        Ok(())
    }
}
