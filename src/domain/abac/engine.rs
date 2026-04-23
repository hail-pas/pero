use super::models::{EvalContext, PolicyCondition};
use regex::RegexBuilder;
use std::collections::HashMap;

const REGEX_SIZE_LIMIT: usize = 1024;

fn subject_values<'a>(ctx: &'a EvalContext, key: &str) -> impl Iterator<Item = &'a str> {
    ctx.subject_attrs
        .get(key)
        .into_iter()
        .flat_map(|values| values.iter().map(String::as_str))
}

pub fn eval_condition(
    cond: &PolicyCondition,
    ctx: &EvalContext,
    regex_cache: &HashMap<String, regex::Regex>,
) -> bool {
    let app_id_str = ctx.app_id.map(|id| id.to_string());
    let target_values: Vec<&str> = match cond.condition_type.as_str() {
        "subject" => subject_values(ctx, &cond.key).collect(),
        "resource" if cond.key == "path" => vec![ctx.resource.as_str()],
        "action" if cond.key == "method" => vec![ctx.action.as_str()],
        "app" if cond.key == "app_id" => app_id_str.as_deref().into_iter().collect(),
        _ => vec![],
    };

    if target_values.is_empty() {
        return false;
    }

    target_values
        .iter()
        .any(|&actual| match cond.operator.as_str() {
            "eq" => actual == cond.value,
            "in" => cond.value.split(',').any(|v| v.trim() == actual),
            "wildcard" => wildcard_match(&cond.value, actual),
            "regex" => regex_cache
                .get(&cond.value)
                .map_or(false, |re| re.is_match(actual)),
            "contains" => actual.contains(&cond.value),
            "gt" => actual.parse::<f64>().ok().map_or(false, |a| {
                cond.value.parse::<f64>().map_or(false, |b| a > b)
            }),
            "lt" => actual.parse::<f64>().ok().map_or(false, |a| {
                cond.value.parse::<f64>().map_or(false, |b| a < b)
            }),
            _ => false,
        })
}

pub fn evaluate(
    policies: &[(super::models::Policy, Vec<PolicyCondition>)],
    ctx: &EvalContext,
    default_action: &str,
) -> String {
    let mut regex_cache: HashMap<String, regex::Regex> = HashMap::new();
    for (_, conditions) in policies {
        for cond in conditions {
            if cond.operator == "regex" && !regex_cache.contains_key(&cond.value) {
                if cond.value.len() <= REGEX_SIZE_LIMIT {
                    match RegexBuilder::new(&cond.value)
                        .size_limit(REGEX_SIZE_LIMIT * 10)
                        .build()
                    {
                        Ok(re) => {
                            regex_cache.insert(cond.value.clone(), re);
                        }
                        Err(e) => {
                            tracing::warn!(
                                pattern = %cond.value,
                                error = %e,
                                "failed to compile regex pattern for ABAC condition"
                            );
                        }
                    }
                }
            }
        }
    }

    for (policy, conditions) in policies {
        if conditions.is_empty() {
            tracing::warn!(
                policy_id = %policy.id,
                "policy has no conditions, skipping evaluation"
            );
            continue;
        }
        if conditions
            .iter()
            .all(|c| eval_condition(c, ctx, &regex_cache))
        {
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
            path.first()
                .map_or(false, |_| wildcard_match_parts(pattern, &path[1..]))
        }
        (Some(_), None) | (None, Some(_)) => false,
        (Some(&p), Some(_)) if p == "*" => wildcard_match_parts(&pattern[1..], &path[1..]),
        (Some(&p), Some(&s)) if p == s => wildcard_match_parts(&pattern[1..], &path[1..]),
        _ => false,
    }
}
