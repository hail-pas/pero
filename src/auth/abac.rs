use sqlx::postgres::PgPool;
use crate::error::AppError;
use serde::{Deserialize, Serialize};

#[derive(Debug, sqlx::FromRow, Serialize, Deserialize)]
pub struct Policy {
    pub id: uuid::Uuid,
    pub name: String,
    pub description: Option<String>,
    pub effect: String,
    pub priority: i32,
    pub enabled: bool,
}

#[derive(Debug, sqlx::FromRow, Serialize, Deserialize)]
pub struct PolicyCondition {
    pub id: uuid::Uuid,
    pub policy_id: uuid::Uuid,
    pub condition_type: String,
    pub key: String,
    pub operator: String,
    pub value: String,
}

#[derive(Debug, sqlx::FromRow)]
pub struct UserAttribute {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Clone)]
pub struct EvalContext {
    pub subject_attrs: Vec<(String, String)>,
    pub resource: String,
    pub action: String,
}

pub async fn load_user_attributes(
    pool: &PgPool,
    user_id: uuid::Uuid,
) -> Result<Vec<(String, String)>, AppError> {
    let attrs: Vec<UserAttribute> = sqlx::query_as(
        "SELECT key, value FROM user_attributes WHERE user_id = $1"
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    Ok(attrs.into_iter().map(|a| (a.key, a.value)).collect())
}

pub async fn load_policies(pool: &PgPool) -> Result<Vec<(Policy, Vec<PolicyCondition>)>, AppError> {
    let policies: Vec<Policy> = sqlx::query_as(
        "SELECT * FROM policies WHERE enabled = true ORDER BY priority DESC"
    )
    .fetch_all(pool)
    .await?;

    let mut result = Vec::new();
    for policy in policies {
        let conditions: Vec<PolicyCondition> = sqlx::query_as(
            "SELECT * FROM policy_conditions WHERE policy_id = $1"
        )
        .bind(policy.id)
        .fetch_all(pool)
        .await?;
        result.push((policy, conditions));
    }
    Ok(result)
}

pub async fn load_user_policies(
    pool: &PgPool,
    user_id: uuid::Uuid,
) -> Result<Vec<(Policy, Vec<PolicyCondition>)>, AppError> {
    let policies: Vec<Policy> = sqlx::query_as(
        "SELECT p.* FROM policies p
         INNER JOIN user_policies up ON up.policy_id = p.id
         WHERE up.user_id = $1 AND p.enabled = true
         ORDER BY p.priority DESC"
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    let mut result = Vec::new();
    for policy in policies {
        let conditions: Vec<PolicyCondition> = sqlx::query_as(
            "SELECT * FROM policy_conditions WHERE policy_id = $1"
        )
        .bind(policy.id)
        .fetch_all(pool)
        .await?;
        result.push((policy, conditions));
    }
    Ok(result)
}

fn eval_condition(cond: &PolicyCondition, ctx: &EvalContext) -> bool {
    let target_value = match cond.condition_type.as_str() {
        "subject" => ctx.subject_attrs.iter().find(|(k, _)| k == &cond.key).map(|(_, v)| v.as_str()),
        "resource" if cond.key == "path" => Some(ctx.resource.as_str()),
        "action" if cond.key == "method" => Some(ctx.action.as_str()),
        _ => None,
    };

    let Some(actual) = target_value else {
        return false;
    };

    match cond.operator.as_str() {
        "eq" => actual == cond.value,
        "in" => cond.value.split(',').any(|v| v.trim() == actual),
        "wildcard" => wildcard_match(&cond.value, actual),
        "regex" => regex::Regex::new(&cond.value)
            .map(|re| re.is_match(actual))
            .unwrap_or(false),
        "contains" => actual.contains(&cond.value),
        _ => false,
    }
}

fn eval_policy(conditions: &[PolicyCondition], ctx: &EvalContext) -> bool {
    conditions.iter().all(|c| eval_condition(c, ctx))
}

pub fn evaluate(
    policies: &[(Policy, Vec<PolicyCondition>)],
    ctx: &EvalContext,
    default_action: &str,
) -> String {
    for (policy, conditions) in policies {
        if eval_policy(conditions, ctx) {
            return policy.effect.clone();
        }
    }
    default_action.to_string()
}

fn wildcard_match(pattern: &str, path: &str) -> bool {
    let pattern_parts: Vec<&str> = pattern.split('/').collect();
    let path_parts: Vec<&str> = path.split('/').collect();
    wildcard_match_parts(&pattern_parts, &path_parts)
}

fn wildcard_match_parts(pattern: &[&str], path: &[&str]) -> bool {
    match (pattern.first(), path.first()) {
        (None, None) => true,
        (Some(&p), _) if p == "**" => {
            if wildcard_match_parts(&pattern[1..], path) {
                return true;
            }
            path.first().map_or(false, |_| wildcard_match_parts(pattern, &path[1..]))
        }
        (Some(_), None) | (None, Some(_)) => false,
        (Some(&p), Some(_)) if p == "*" => wildcard_match_parts(&pattern[1..], &path[1..]),
        (Some(&p), Some(&s)) if p == s => wildcard_match_parts(&pattern[1..], &path[1..]),
        _ => false,
    }
}
