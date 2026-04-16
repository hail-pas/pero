use crate::shared::error::AppError;
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgPool;
use utoipa::ToSchema;
use validator::Validate;

#[derive(Debug, sqlx::FromRow, Serialize, ToSchema)]
pub struct UserAttribute {
    pub id: uuid::Uuid,
    pub user_id: uuid::Uuid,
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

pub struct UserAttributeRepo;

impl UserAttributeRepo {
    pub async fn list_by_user(
        pool: &PgPool,
        user_id: uuid::Uuid,
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
        user_id: uuid::Uuid,
        items: &[AttributeItem],
    ) -> Result<(), AppError> {
        for item in items {
            sqlx::query(
                "INSERT INTO user_attributes (user_id, key, value) VALUES ($1, $2, $3)
                 ON CONFLICT (user_id, key) DO UPDATE SET value = EXCLUDED.value",
            )
            .bind(user_id)
            .bind(&item.key)
            .bind(&item.value)
            .execute(pool)
            .await?;
        }
        Ok(())
    }

    pub async fn delete_by_user(
        pool: &PgPool,
        user_id: uuid::Uuid,
        key: &str,
    ) -> Result<(), AppError> {
        sqlx::query("DELETE FROM user_attributes WHERE user_id = $1 AND key = $2")
            .bind(user_id)
            .bind(key)
            .execute(pool)
            .await?;
        Ok(())
    }
}
