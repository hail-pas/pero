use std::sync::Arc;

use sqlx::postgres::PgPool;
use uuid::Uuid;

use crate::domain::user::dto::{AttributeItem, UserAttribute};
use crate::domain::user::repo::UserAttributeStore;
use crate::shared::error::AppError;

pub struct SqlxUserAttributeStore {
    pool: Arc<PgPool>,
}

impl SqlxUserAttributeStore {
    pub fn new(pool: Arc<PgPool>) -> Self {
        Self { pool }
    }
}
#[async_trait::async_trait]
impl UserAttributeStore for SqlxUserAttributeStore {
    async fn list_by_user(&self, user_id: Uuid) -> Result<Vec<UserAttribute>, AppError> {
        let attrs = sqlx::query_as::<_, UserAttribute>(
            "SELECT * FROM user_attributes WHERE user_id = $1 ORDER BY key",
        )
        .bind(user_id)
        .fetch_all(&*self.pool)
        .await?;
        Ok(attrs)
    }

    async fn upsert(&self, user_id: Uuid, items: &[AttributeItem]) -> Result<(), AppError> {
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
        .execute(&*self.pool)
        .await?;
        Ok(())
    }

    async fn delete_by_user(&self, user_id: Uuid, key: &str) -> Result<(), AppError> {
        sqlx::query("DELETE FROM user_attributes WHERE user_id = $1 AND key = $2")
            .bind(user_id)
            .bind(key)
            .execute(&*self.pool)
            .await?;
        Ok(())
    }
}
