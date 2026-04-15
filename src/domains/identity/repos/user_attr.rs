use crate::shared::error::AppError;
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgPool;

#[derive(Debug, sqlx::FromRow, Serialize)]
pub struct UserAttribute {
    pub id: uuid::Uuid,
    pub user_id: uuid::Uuid,
    pub key: String,
    pub value: String,
}

#[derive(Debug, Deserialize)]
pub struct SetAttributes {
    pub attributes: Vec<AttributeItem>,
}

#[derive(Debug, Deserialize)]
pub struct AttributeItem {
    pub key: String,
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

    #[allow(dead_code)]
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
