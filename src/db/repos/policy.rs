use sqlx::postgres::PgPool;
use crate::error::AppError;
use crate::auth::abac::{Policy, PolicyCondition};
use serde::Deserialize;
use validator::Validate;

#[derive(Debug, Deserialize, Validate)]
pub struct CreatePolicy {
    #[validate(length(min = 1, max = 128))]
    pub name: String,
    pub description: Option<String>,
    #[validate(length(min = 1))]
    pub effect: String,
    #[validate(range(min = 0))]
    pub priority: i32,
    pub enabled: Option<bool>,
    pub conditions: Vec<CreateCondition>,
}

#[derive(Debug, Deserialize, Validate)]
pub struct CreateCondition {
    #[validate(length(min = 1))]
    pub condition_type: String,
    #[validate(length(min = 1))]
    pub key: String,
    #[validate(length(min = 1))]
    pub operator: String,
    #[validate(length(min = 1))]
    pub value: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct UpdatePolicy {
    #[validate(length(min = 1, max = 128))]
    pub name: Option<String>,
    pub description: Option<String>,
    #[validate(length(min = 1))]
    pub effect: Option<String>,
    pub priority: Option<i32>,
    pub enabled: Option<bool>,
    pub conditions: Option<Vec<CreateCondition>>,
}

pub struct PolicyRepo;

impl PolicyRepo {
    pub async fn create(pool: &PgPool, input: &CreatePolicy) -> Result<Policy, AppError> {
        let enabled = input.enabled.unwrap_or(true);
        let policy = sqlx::query_as::<_, Policy>(
            "INSERT INTO policies (name, description, effect, priority, enabled) VALUES ($1, $2, $3, $4, $5) RETURNING *"
        )
        .bind(&input.name)
        .bind(&input.description)
        .bind(&input.effect)
        .bind(input.priority)
        .bind(enabled)
        .fetch_one(pool)
        .await?;

        for cond in &input.conditions {
            sqlx::query(
                "INSERT INTO policy_conditions (policy_id, condition_type, key, operator, value) VALUES ($1, $2, $3, $4, $5)"
            )
            .bind(policy.id)
            .bind(&cond.condition_type)
            .bind(&cond.key)
            .bind(&cond.operator)
            .bind(&cond.value)
            .execute(pool)
            .await?;
        }

        Ok(policy)
    }

    pub async fn find_by_id(pool: &PgPool, id: uuid::Uuid) -> Result<Option<Policy>, AppError> {
        let policy = sqlx::query_as::<_, Policy>("SELECT * FROM policies WHERE id = $1")
            .bind(id)
            .fetch_optional(pool)
            .await?;
        Ok(policy)
    }

    pub async fn list(pool: &PgPool) -> Result<Vec<Policy>, AppError> {
        let policies = sqlx::query_as::<_, Policy>(
            "SELECT * FROM policies ORDER BY priority DESC"
        )
        .fetch_all(pool)
        .await?;
        Ok(policies)
    }

    pub async fn update(pool: &PgPool, id: uuid::Uuid, input: &UpdatePolicy) -> Result<Policy, AppError> {
        let existing = Self::find_by_id(pool, id)
            .await?
            .ok_or(AppError::NotFound("policy".into()))?;

        let name = input.name.as_deref().unwrap_or(&existing.name);
        let description = input.description.as_ref().or(existing.description.as_ref());
        let effect = input.effect.as_deref().unwrap_or(&existing.effect);
        let priority = input.priority.unwrap_or(existing.priority);
        let enabled = input.enabled.unwrap_or(existing.enabled);

        let policy = sqlx::query_as::<_, Policy>(
            "UPDATE policies SET name = $1, description = $2, effect = $3, priority = $4, enabled = $5 WHERE id = $6 RETURNING *"
        )
        .bind(name)
        .bind(description)
        .bind(effect)
        .bind(priority)
        .bind(enabled)
        .bind(id)
        .fetch_one(pool)
        .await?;

        // If conditions provided, replace them
        if let Some(conditions) = &input.conditions {
            sqlx::query("DELETE FROM policy_conditions WHERE policy_id = $1")
                .bind(id)
                .execute(pool)
                .await?;

            for cond in conditions {
                sqlx::query(
                    "INSERT INTO policy_conditions (policy_id, condition_type, key, operator, value) VALUES ($1, $2, $3, $4, $5)"
                )
                .bind(id)
                .bind(&cond.condition_type)
                .bind(&cond.key)
                .bind(&cond.operator)
                .bind(&cond.value)
                .execute(pool)
                .await?;
            }
        }

        Ok(policy)
    }

    pub async fn delete(pool: &PgPool, id: uuid::Uuid) -> Result<(), AppError> {
        let result = sqlx::query("DELETE FROM policies WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await?;
        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("policy".into()));
        }
        Ok(())
    }

    pub async fn get_conditions(pool: &PgPool, policy_id: uuid::Uuid) -> Result<Vec<PolicyCondition>, AppError> {
        let conditions = sqlx::query_as::<_, PolicyCondition>(
            "SELECT * FROM policy_conditions WHERE policy_id = $1"
        )
        .bind(policy_id)
        .fetch_all(pool)
        .await?;
        Ok(conditions)
    }
}
