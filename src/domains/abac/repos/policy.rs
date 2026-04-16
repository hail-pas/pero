use super::super::models::{
    CreatePolicyRequest, Policy, PolicyCondition, UpdatePolicyRequest, UserAttribute,
};
use crate::shared::error::AppError;
use sqlx::postgres::PgPool;
use std::collections::HashMap;
use uuid::Uuid;

pub struct PolicyRepo;

impl PolicyRepo {
    pub async fn create(pool: &PgPool, req: &CreatePolicyRequest) -> Result<Policy, AppError> {
        let policy = sqlx::query_as::<_, Policy>(
            "INSERT INTO policies (name, description, effect, priority, enabled, app_id) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *"
        )
        .bind(&req.name)
        .bind(&req.description)
        .bind(&req.effect)
        .bind(req.priority)
        .bind(req.enabled)
        .bind(req.app_id)
        .fetch_one(pool)
        .await?;

        for cond in &req.conditions {
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

    pub async fn find_by_id(pool: &PgPool, id: Uuid) -> Result<Option<Policy>, AppError> {
        sqlx::query_as::<_, Policy>("SELECT * FROM policies WHERE id = $1")
            .bind(id)
            .fetch_optional(pool)
            .await
            .map_err(Into::into)
    }

    pub async fn list(
        pool: &PgPool,
        page: i64,
        page_size: i64,
    ) -> Result<(Vec<Policy>, i64), AppError> {
        let offset = (page - 1) * page_size;
        let policies = sqlx::query_as::<_, Policy>(
            "SELECT * FROM policies ORDER BY priority DESC LIMIT $1 OFFSET $2",
        )
        .bind(page_size)
        .bind(offset)
        .fetch_all(pool)
        .await?;

        let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM policies")
            .fetch_one(pool)
            .await?;

        Ok((policies, total))
    }

    pub async fn update(
        pool: &PgPool,
        id: Uuid,
        req: &UpdatePolicyRequest,
    ) -> Result<Policy, AppError> {
        let policy = Self::find_by_id(pool, id)
            .await?
            .ok_or(AppError::NotFound("policy".into()))?;

        let name = req.name.as_deref().unwrap_or(&policy.name);
        let description = req.description.as_deref().or(policy.description.as_deref());
        let effect = req.effect.as_deref().unwrap_or(&policy.effect);
        let priority = req.priority.unwrap_or(policy.priority);
        let enabled = req.enabled.unwrap_or(policy.enabled);
        let app_id = req.app_id.as_ref().or(policy.app_id.as_ref());

        let updated = sqlx::query_as::<_, Policy>(
            "UPDATE policies SET name = $1, description = $2, effect = $3, priority = $4, enabled = $5, app_id = $6 WHERE id = $7 RETURNING *"
        )
        .bind(name)
        .bind(description)
        .bind(effect)
        .bind(priority)
        .bind(enabled)
        .bind(app_id)
        .bind(id)
        .fetch_one(pool)
        .await?;

        if let Some(conditions) = &req.conditions {
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

        Ok(updated)
    }

    pub async fn delete(pool: &PgPool, id: Uuid) -> Result<(), AppError> {
        let result = sqlx::query("DELETE FROM policies WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await?;
        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("policy".into()));
        }
        Ok(())
    }

    pub async fn get_conditions(
        pool: &PgPool,
        policy_id: Uuid,
    ) -> Result<Vec<PolicyCondition>, AppError> {
        sqlx::query_as::<_, PolicyCondition>("SELECT * FROM policy_conditions WHERE policy_id = $1")
            .bind(policy_id)
            .fetch_all(pool)
            .await
            .map_err(Into::into)
    }

    pub async fn batch_get_conditions_map(
        pool: &PgPool,
        policy_ids: &[Uuid],
    ) -> Result<HashMap<Uuid, Vec<PolicyCondition>>, AppError> {
        if policy_ids.is_empty() {
            return Ok(HashMap::new());
        }
        let conditions: Vec<PolicyCondition> =
            sqlx::query_as("SELECT * FROM policy_conditions WHERE policy_id = ANY($1)")
                .bind(policy_ids)
                .fetch_all(pool)
                .await?;

        let mut map: HashMap<Uuid, Vec<PolicyCondition>> = HashMap::new();
        for cond in conditions {
            map.entry(cond.policy_id).or_default().push(cond);
        }
        Ok(map)
    }

    pub async fn load_user_attributes(
        pool: &PgPool,
        user_id: Uuid,
    ) -> Result<Vec<(String, String)>, AppError> {
        let attrs: Vec<UserAttribute> =
            sqlx::query_as("SELECT key, value FROM user_attributes WHERE user_id = $1")
                .bind(user_id)
                .fetch_all(pool)
                .await?;

        Ok(attrs.into_iter().map(|a| (a.key, a.value)).collect())
    }

    pub async fn load_policies_for_app(
        pool: &PgPool,
        app_id: Option<Uuid>,
    ) -> Result<Vec<(Policy, Vec<PolicyCondition>)>, AppError> {
        let policies: Vec<Policy> = sqlx::query_as(
            "SELECT * FROM policies WHERE enabled = true AND (app_id = $1 OR app_id IS NULL) ORDER BY priority DESC"
        )
        .bind(app_id)
        .fetch_all(pool)
        .await?;

        let ids: Vec<Uuid> = policies.iter().map(|p| p.id).collect();
        let conditions_map = Self::batch_get_conditions_map(pool, &ids).await?;

        Ok(policies
            .into_iter()
            .map(|p| {
                let conds = conditions_map.get(&p.id).cloned().unwrap_or_default();
                (p, conds)
            })
            .collect())
    }

    pub async fn assign_policy_to_user(
        pool: &PgPool,
        user_id: Uuid,
        policy_id: Uuid,
    ) -> Result<(), AppError> {
        let exists: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM policies WHERE id = $1)")
                .bind(policy_id)
                .fetch_one(pool)
                .await?;
        if !exists {
            return Err(AppError::NotFound("policy".into()));
        }

        let user_exists: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE id = $1)")
                .bind(user_id)
                .fetch_one(pool)
                .await?;
        if !user_exists {
            return Err(AppError::NotFound("user".into()));
        }

        sqlx::query(
            "INSERT INTO user_policies (user_id, policy_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
        )
        .bind(user_id)
        .bind(policy_id)
        .execute(pool)
        .await?;
        Ok(())
    }

    pub async fn unassign_policy_from_user(
        pool: &PgPool,
        user_id: Uuid,
        policy_id: Uuid,
    ) -> Result<(), AppError> {
        let result = sqlx::query("DELETE FROM user_policies WHERE user_id = $1 AND policy_id = $2")
            .bind(user_id)
            .bind(policy_id)
            .execute(pool)
            .await?;
        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("user_policy assignment".into()));
        }
        Ok(())
    }

    pub async fn list_user_assignments(
        pool: &PgPool,
        user_id: Uuid,
    ) -> Result<Vec<Policy>, AppError> {
        sqlx::query_as::<_, Policy>(
            "SELECT p.* FROM policies p
             INNER JOIN user_policies up ON up.policy_id = p.id
             WHERE up.user_id = $1
             ORDER BY p.priority DESC",
        )
        .bind(user_id)
        .fetch_all(pool)
        .await
        .map_err(Into::into)
    }

    pub async fn load_user_policies_for_app(
        pool: &PgPool,
        user_id: Uuid,
        app_id: Option<Uuid>,
    ) -> Result<Vec<(Policy, Vec<PolicyCondition>)>, AppError> {
        let policies: Vec<Policy> = sqlx::query_as(
            "SELECT p.* FROM policies p
             INNER JOIN user_policies up ON up.policy_id = p.id
             WHERE up.user_id = $1 AND p.enabled = true AND (p.app_id = $2 OR p.app_id IS NULL)
             ORDER BY p.priority DESC",
        )
        .bind(user_id)
        .bind(app_id)
        .fetch_all(pool)
        .await?;

        let ids: Vec<Uuid> = policies.iter().map(|p| p.id).collect();
        let conditions_map = Self::batch_get_conditions_map(pool, &ids).await?;

        Ok(policies
            .into_iter()
            .map(|p| {
                let conds = conditions_map.get(&p.id).cloned().unwrap_or_default();
                (p, conds)
            })
            .collect())
    }
}
