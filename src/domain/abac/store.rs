use crate::domain::abac::error;
use crate::domain::abac::models::{
    CreateConditionRequest, CreatePolicyRequest, Policy, PolicyCondition, UpdatePolicyRequest,
    UserAttribute,
};
use crate::shared::error::{AppError, require_found};
use crate::shared::pagination::{offset, paginate, POLICIES};
use sqlx::postgres::PgPool;
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Debug, Clone, Copy)]
pub struct PolicyFilter {
    pub user_id: Option<Uuid>,
    pub app_id: Option<Uuid>,
    pub include_global: bool,
    pub enabled_only: bool,
}

pub struct PolicyRepo;

impl PolicyRepo {
    pub async fn create(
        pool: &PgPool,
        req: &CreatePolicyRequest,
    ) -> Result<(Policy, Vec<PolicyCondition>), AppError> {
        let mut tx = pool.begin().await?;

        let policy = sqlx::query_as::<_, Policy>(
            "INSERT INTO policies (name, description, effect, priority, enabled, app_id) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *"
        )
        .bind(&req.name)
        .bind(&req.description)
        .bind(req.effect.as_str())
        .bind(req.priority)
        .bind(req.enabled)
        .bind(req.app_id)
        .fetch_one(&mut *tx)
        .await?;

        let conditions = PolicyConditionRepo::create_batch_in_tx(&mut tx, policy.id, &req.conditions).await?;

        tx.commit().await?;
        Ok((policy, conditions))
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
        paginate(pool, POLICIES, page, page_size).await
    }

    pub async fn update(
        pool: &PgPool,
        id: Uuid,
        req: &UpdatePolicyRequest,
    ) -> Result<(Policy, Vec<PolicyCondition>), AppError> {
        let policy = require_found(Self::find_by_id(pool, id).await?, "policy")?;
        Self::update_with_policy(pool, id, req, &policy).await
    }

    pub async fn update_with_policy(
        pool: &PgPool,
        id: Uuid,
        req: &UpdatePolicyRequest,
        policy: &Policy,
    ) -> Result<(Policy, Vec<PolicyCondition>), AppError> {
        let mut tx = pool.begin().await?;

        let name = req.name.as_deref().unwrap_or(&policy.name);
        let description = req.description.as_deref().or(policy.description.as_deref());
        let effect = req
            .effect
            .as_ref()
            .map(|e| e.as_str())
            .unwrap_or(&policy.effect);
        let priority = req.priority.unwrap_or(policy.priority);
        let enabled = req.enabled.unwrap_or(policy.enabled);
        let app_id = req.app_id.as_ref().or(policy.app_id.as_ref());

        let updated = sqlx::query_as::<_, Policy>(
            "UPDATE policies SET name = $1, description = $2, effect = $3, priority = $4, enabled = $5, app_id = $6, updated_at = now() WHERE id = $7 RETURNING *"
        )
        .bind(name)
        .bind(description)
        .bind(effect)
        .bind(priority)
        .bind(enabled)
        .bind(app_id)
        .bind(id)
        .fetch_one(&mut *tx)
        .await?;

        let conditions = if let Some(conditions_req) = &req.conditions {
            PolicyConditionRepo::delete_for_policy(&mut tx, id).await?;
            PolicyConditionRepo::create_batch_in_tx(&mut tx, id, conditions_req).await?
        } else {
            PolicyConditionRepo::get_for_policy_in_tx(&mut tx, id).await?
        };

        tx.commit().await?;
        Ok((updated, conditions))
    }

    pub async fn delete(pool: &PgPool, id: Uuid) -> Result<(), AppError> {
        let result = sqlx::query("DELETE FROM policies WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await?;
        if result.rows_affected() == 0 {
            return Err(error::policy_not_found());
        }
        Ok(())
    }

    pub async fn attach_conditions(
        pool: &PgPool,
        policies: Vec<Policy>,
    ) -> Result<Vec<(Policy, Vec<PolicyCondition>)>, AppError> {
        let ids: Vec<Uuid> = policies.iter().map(|p| p.id).collect();
        let conditions_map = PolicyConditionRepo::batch_get_map(pool, &ids).await?;
        Ok(policies
            .into_iter()
            .map(|p| {
                let conds = conditions_map.get(&p.id).cloned().unwrap_or_default();
                (p, conds)
            })
            .collect())
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

    pub async fn load_policies(
        pool: &PgPool,
        filter: PolicyFilter,
    ) -> Result<Vec<(Policy, Vec<PolicyCondition>)>, AppError> {
        let policies = Self::select_policies(pool, filter).await?;
        Self::attach_conditions(pool, policies).await
    }

    async fn select_policies(pool: &PgPool, filter: PolicyFilter) -> Result<Vec<Policy>, AppError> {
        let mut builder = sqlx::QueryBuilder::<sqlx::Postgres>::new(
            "SELECT p.* FROM policies p",
        );

        if filter.user_id.is_some() {
            builder.push(" INNER JOIN user_policies up ON up.policy_id = p.id");
        }

        let mut has_clause = false;
        if let Some(user_id) = filter.user_id {
            push_clause_separator(&mut builder, &mut has_clause);
            builder.push("up.user_id = ");
            builder.push_bind(user_id);
        }
        if filter.enabled_only {
            push_clause_separator(&mut builder, &mut has_clause);
            builder.push("p.enabled = true");
        }
        match filter.app_id {
            Some(app_id) if filter.include_global => {
                push_clause_separator(&mut builder, &mut has_clause);
                builder.push("(p.app_id = ");
                builder.push_bind(app_id);
                builder.push(" OR p.app_id IS NULL)");
            }
            Some(app_id) => {
                push_clause_separator(&mut builder, &mut has_clause);
                builder.push("p.app_id = ");
                builder.push_bind(app_id);
            }
            None if !filter.include_global => {
                push_clause_separator(&mut builder, &mut has_clause);
                builder.push("p.app_id IS NULL");
            }
            None => {}
        }

        builder.push(" ORDER BY p.priority DESC");
        builder
            .build_query_as::<Policy>()
            .fetch_all(pool)
            .await
            .map_err(Into::into)
    }

    pub async fn list_by_app(
        pool: &PgPool,
        app_id: Uuid,
        page: i64,
        page_size: i64,
    ) -> Result<(Vec<Policy>, i64), AppError> {
        let off = offset(page, page_size);
        let policies = sqlx::query_as::<_, Policy>(
            "SELECT * FROM policies WHERE app_id = $1 ORDER BY priority DESC LIMIT $2 OFFSET $3",
        )
        .bind(app_id)
        .bind(page_size)
        .bind(off)
        .fetch_all(pool)
        .await?;

        let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM policies WHERE app_id = $1")
            .bind(app_id)
            .fetch_one(pool)
            .await?;

        Ok((policies, total))
    }

    pub async fn load_user_policies_for_app(
        pool: &PgPool,
        user_id: Uuid,
        app_id: Option<Uuid>,
    ) -> Result<Vec<(Policy, Vec<PolicyCondition>)>, AppError> {
        Self::load_policies(
            pool,
            PolicyFilter {
                user_id: Some(user_id),
                app_id,
                include_global: app_id.is_some(),
                enabled_only: true,
            },
        )
        .await
    }
}

fn push_clause_separator(
    builder: &mut sqlx::QueryBuilder<'_, sqlx::Postgres>,
    has_clause: &mut bool,
) {
    if *has_clause {
        builder.push(" AND ");
    } else {
        builder.push(" WHERE ");
        *has_clause = true;
    }
}

pub struct PolicyConditionRepo;

impl PolicyConditionRepo {
    pub async fn create_batch_in_tx(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        policy_id: Uuid,
        conditions: &[CreateConditionRequest],
    ) -> Result<Vec<PolicyCondition>, AppError> {
        let mut result = Vec::with_capacity(conditions.len());
        for cond in conditions {
            let c = sqlx::query_as::<_, PolicyCondition>(
                "INSERT INTO policy_conditions (policy_id, condition_type, key, operator, value) VALUES ($1, $2, $3, $4, $5) RETURNING *"
            )
            .bind(policy_id)
            .bind(cond.condition_type.as_str())
            .bind(&cond.key)
            .bind(cond.operator.as_str())
            .bind(&cond.value)
            .fetch_one(&mut **tx)
            .await?;
            result.push(c);
        }
        Ok(result)
    }

    pub async fn get_for_policy(
        pool: &PgPool,
        policy_id: Uuid,
    ) -> Result<Vec<PolicyCondition>, AppError> {
        sqlx::query_as::<_, PolicyCondition>(
            "SELECT * FROM policy_conditions WHERE policy_id = $1",
        )
        .bind(policy_id)
        .fetch_all(pool)
        .await
        .map_err(Into::into)
    }

    pub async fn get_for_policy_in_tx(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        policy_id: Uuid,
    ) -> Result<Vec<PolicyCondition>, AppError> {
        sqlx::query_as::<_, PolicyCondition>(
            "SELECT * FROM policy_conditions WHERE policy_id = $1",
        )
        .bind(policy_id)
        .fetch_all(&mut **tx)
        .await
        .map_err(Into::into)
    }

    pub async fn batch_get_map(
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

    pub async fn delete_for_policy(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        policy_id: Uuid,
    ) -> Result<(), AppError> {
        sqlx::query("DELETE FROM policy_conditions WHERE policy_id = $1")
            .bind(policy_id)
            .execute(&mut **tx)
            .await?;
        Ok(())
    }
}

pub struct UserPolicyRepo;

impl UserPolicyRepo {
    pub async fn assign(
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
            return Err(error::policy_not_found());
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

    pub async fn unassign(
        pool: &PgPool,
        user_id: Uuid,
        policy_id: Uuid,
    ) -> Result<(), AppError> {
        let result =
            sqlx::query("DELETE FROM user_policies WHERE user_id = $1 AND policy_id = $2")
                .bind(user_id)
                .bind(policy_id)
                .execute(pool)
                .await?;
        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("user_policy assignment".into()));
        }
        Ok(())
    }

    pub async fn list_user_policies(
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

    pub async fn list_user_policies_by_app(
        pool: &PgPool,
        user_id: Uuid,
        app_id: Uuid,
    ) -> Result<Vec<Policy>, AppError> {
        sqlx::query_as::<_, Policy>(
            "SELECT p.* FROM policies p
             INNER JOIN user_policies up ON up.policy_id = p.id
             WHERE up.user_id = $1 AND p.app_id = $2
             ORDER BY p.priority DESC",
        )
        .bind(user_id)
        .bind(app_id)
        .fetch_all(pool)
        .await
        .map_err(Into::into)
    }
}
