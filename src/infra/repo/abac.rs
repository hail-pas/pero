use std::collections::HashMap;
use std::sync::Arc;

use sqlx::postgres::PgPool;
use uuid::Uuid;

use crate::domain::abac::dto::CreateConditionRequest;
use crate::domain::abac::models::{CreatePolicyRequest, Policy, PolicyCondition, UpdatePolicyRequest, UserAttribute};
use crate::domain::abac::repo::{AbacCacheStore, AbacStore};
use crate::domain::abac::service::AttachedPolicies;
use crate::domain::abac::store::PolicyFilter;
use crate::infra::cache;
use crate::shared::cache_keys::abac::{
    app_version_key, policy_key, policy_version_key, subject_key, subject_version_key,
};
use crate::shared::error::{AppError, require_found, require_rows_affected};
use crate::shared::pagination::{POLICIES, offset, paginate};
use crate::shared::patch::Patch;

pub struct SqlxAbacStore {
    pool: Arc<PgPool>,
}

impl SqlxAbacStore {
    pub fn new(pool: Arc<PgPool>) -> Self {
        Self { pool }
    }
}

pub struct RedisAbacCacheStore {
    pool: cache::Pool,
}

impl RedisAbacCacheStore {
    pub fn new(pool: cache::Pool) -> Self {
        Self { pool }
    }
}

#[async_trait::async_trait]
impl AbacStore for SqlxAbacStore {
    async fn create_policy(
        &self,
        req: &CreatePolicyRequest,
    ) -> Result<(Policy, Vec<PolicyCondition>), AppError> {
        let mut tx = self.pool.begin().await?;

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

        let conditions = create_conditions_batch(&mut tx, policy.id, &req.conditions).await?;

        tx.commit().await?;
        Ok((policy, conditions))
    }

    async fn find_policy_by_id(&self, id: Uuid) -> Result<Option<Policy>, AppError> {
        sqlx::query_as::<_, Policy>("SELECT * FROM policies WHERE id = $1")
            .bind(id)
            .fetch_optional(&*self.pool)
            .await
            .map_err(Into::into)
    }

    async fn list_policies(
        &self,
        page: i64,
        page_size: i64,
    ) -> Result<(Vec<Policy>, i64), AppError> {
        paginate(&self.pool, POLICIES, page, page_size).await
    }

    async fn list_policies_by_app(
        &self,
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
        .fetch_all(&*self.pool)
        .await?;

        let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM policies WHERE app_id = $1")
            .bind(app_id)
            .fetch_one(&*self.pool)
            .await?;

        Ok((policies, total))
    }

    async fn update_policy(
        &self,
        id: Uuid,
        req: &UpdatePolicyRequest,
        policy: &Policy,
    ) -> Result<(Policy, Vec<PolicyCondition>), AppError> {
        let mut tx = self.pool.begin().await?;

        let name = req
            .name
            .as_set()
            .map(|s| s.as_str())
            .unwrap_or(&policy.name);
        let description = req
            .description
            .as_set()
            .map(|s| s.as_str())
            .or_else(|| policy.description.as_deref());
        let effect = req
            .effect
            .as_set()
            .map(|e| e.as_str())
            .unwrap_or(&policy.effect);
        let priority = req.priority.as_set().copied().unwrap_or(policy.priority);
        let enabled = req.enabled.as_set().copied().unwrap_or(policy.enabled);
        let app_id = req.app_id.as_set().or(policy.app_id.as_ref());

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

        let conditions = if let Patch::Set(conditions_req) = &req.conditions {
            sqlx::query("DELETE FROM policy_conditions WHERE policy_id = $1")
                .bind(id)
                .execute(&mut *tx)
                .await?;
            create_conditions_batch(&mut tx, id, conditions_req).await?
        } else {
            sqlx::query_as::<_, PolicyCondition>(
                "SELECT * FROM policy_conditions WHERE policy_id = $1",
            )
            .bind(id)
            .fetch_all(&mut *tx)
            .await?
        };

        tx.commit().await?;
        Ok((updated, conditions))
    }

    async fn delete_policy(&self, id: Uuid) -> Result<(), AppError> {
        let result = sqlx::query("DELETE FROM policies WHERE id = $1")
            .bind(id)
            .execute(&*self.pool)
            .await?;
        require_rows_affected(result, "policy")
    }

    async fn select_policies(&self, filter: PolicyFilter) -> Result<Vec<Policy>, AppError> {
        let mut builder = sqlx::QueryBuilder::<sqlx::Postgres>::new("SELECT p.* FROM policies p");

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
            Some(app_id) => {
                push_clause_separator(&mut builder, &mut has_clause);
                builder.push("(p.app_id = ");
                builder.push_bind(app_id);
                builder.push(" OR p.app_id IS NULL)");
            }
            None => {
                push_clause_separator(&mut builder, &mut has_clause);
                builder.push("p.app_id IS NULL");
            }
        }

        builder.push(" ORDER BY p.priority DESC, p.effect DESC, p.id ASC");
        builder
            .build_query_as::<Policy>()
            .fetch_all(&*self.pool)
            .await
            .map_err(Into::into)
    }

    async fn attach_conditions(
        &self,
        policies: Vec<Policy>,
    ) -> Result<Vec<(Policy, Vec<PolicyCondition>)>, AppError> {
        let ids: Vec<Uuid> = policies.iter().map(|p| p.id).collect();
        let conditions_map = batch_get_conditions_map(&self.pool, &ids).await?;
        Ok(policies
            .into_iter()
            .map(|p| {
                let conds = conditions_map.get(&p.id).cloned().unwrap_or_default();
                (p, conds)
            })
            .collect())
    }

    async fn load_user_attributes(&self, user_id: Uuid) -> Result<Vec<(String, String)>, AppError> {
        let attrs: Vec<UserAttribute> =
            sqlx::query_as("SELECT key, value FROM user_attributes WHERE user_id = $1")
                .bind(user_id)
                .fetch_all(&*self.pool)
                .await?;
        Ok(attrs.into_iter().map(|a| (a.key, a.value)).collect())
    }

    async fn assign_policy(&self, user_id: Uuid, policy_id: Uuid) -> Result<(), AppError> {
        let policy = sqlx::query_as::<_, Policy>("SELECT * FROM policies WHERE id = $1")
            .bind(policy_id)
            .fetch_optional(&*self.pool)
            .await?;
        require_found(policy, "policy")?;
        let user = sqlx::query_as::<_, crate::domain::identity::entity::User>(
            "SELECT * FROM users WHERE id = $1",
        )
        .bind(user_id)
        .fetch_optional(&*self.pool)
        .await?;
        require_found(user, "user")?;

        sqlx::query(
            "INSERT INTO user_policies (user_id, policy_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
        )
        .bind(user_id)
        .bind(policy_id)
        .execute(&*self.pool)
        .await?;
        Ok(())
    }

    async fn unassign_policy(&self, user_id: Uuid, policy_id: Uuid) -> Result<(), AppError> {
        let result = sqlx::query("DELETE FROM user_policies WHERE user_id = $1 AND policy_id = $2")
            .bind(user_id)
            .bind(policy_id)
            .execute(&*self.pool)
            .await?;
        if result.rows_affected() == 0 {
            return Err(AppError::NotFound("user_policy assignment".into()));
        }
        Ok(())
    }
}

async fn create_conditions_batch(
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

async fn batch_get_conditions_map(
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

#[async_trait::async_trait]
impl AbacCacheStore for RedisAbacCacheStore {
    async fn get_subject_attrs(
        &self,
        user_id: Uuid,
    ) -> Result<Option<HashMap<String, Vec<String>>>, AppError> {
        read_versioned(
            &self.pool,
            &subject_key(user_id),
            &subject_version_key(user_id),
        )
        .await
    }

    async fn set_subject_attrs(
        &self,
        user_id: Uuid,
        attrs: &HashMap<String, Vec<String>>,
        ttl: i64,
    ) -> Result<(), AppError> {
        write_versioned(
            &self.pool,
            &subject_key(user_id),
            &subject_version_key(user_id),
            attrs,
            ttl,
        )
        .await
    }

    async fn get_policies(
        &self,
        user_id: Uuid,
        app_id: Option<Uuid>,
    ) -> Result<Option<AttachedPolicies>, AppError> {
        read_versioned(
            &self.pool,
            &policy_key(user_id, app_id),
            &policy_version_key(user_id, app_id),
        )
        .await
    }

    async fn set_policies(
        &self,
        user_id: Uuid,
        app_id: Option<Uuid>,
        policies: &AttachedPolicies,
        ttl: i64,
    ) -> Result<(), AppError> {
        write_versioned(
            &self.pool,
            &policy_key(user_id, app_id),
            &policy_version_key(user_id, app_id),
            policies,
            ttl,
        )
        .await
    }

    async fn bump_policy_version(&self, app_id: Option<Uuid>, ttl: i64) -> Result<(), AppError> {
        let new_version = Uuid::new_v4().to_string();
        cache::set(&self.pool, &app_version_key(app_id), &new_version, ttl).await
    }

    async fn bump_user_version(&self, user_id: Uuid, ttl: i64) -> Result<(), AppError> {
        {
            let new_version = Uuid::new_v4().to_string();
            cache::set(
                &self.pool,
                &policy_version_key(user_id, None),
                &new_version,
                ttl,
            )
            .await?;
        }
        let new_version = Uuid::new_v4().to_string();
        cache::set(
            &self.pool,
            &subject_version_key(user_id),
            &new_version,
            ttl,
        )
        .await
    }
}

async fn read_versioned<T: serde::de::DeserializeOwned>(
    pool: &cache::Pool,
    base_key: &str,
    version_key: &str,
) -> Result<Option<T>, AppError> {
    let version: Option<String> = cache::get(pool, version_key).await?;
    match version {
        Some(v) => {
            let keyed = format!("{}:{}", base_key, v);
            cache::get_json(pool, &keyed).await
        }
        None => Ok(None),
    }
}

async fn write_versioned<T: serde::Serialize>(
    pool: &cache::Pool,
    base_key: &str,
    version_key: &str,
    value: &T,
    ttl: i64,
) -> Result<(), AppError> {
    let version = Uuid::new_v4().to_string();
    let keyed = format!("{}:{}", base_key, version);
    cache::set_json(pool, &keyed, value, ttl).await?;
    cache::set(pool, version_key, &version, ttl).await?;
    Ok(())
}
