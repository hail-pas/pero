use super::models::{EvalContext, PolicyCondition};

pub fn eval_condition(cond: &PolicyCondition, ctx: &EvalContext) -> bool {
    let target_value = match cond.condition_type.as_str() {
        "subject" => ctx
            .subject_attrs
            .iter()
            .find(|(k, _)| k == &cond.key)
            .map(|(_, v)| v.as_str()),
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
        "gt" => actual.parse::<f64>().ok().map_or(false, |a| {
            cond.value.parse::<f64>().map_or(false, |b| a > b)
        }),
        "lt" => actual.parse::<f64>().ok().map_or(false, |a| {
            cond.value.parse::<f64>().map_or(false, |b| a < b)
        }),
        _ => false,
    }
}

pub fn evaluate(
    policies: &[(super::models::Policy, Vec<PolicyCondition>)],
    ctx: &EvalContext,
    default_action: &str,
) -> String {
    for (policy, conditions) in policies {
        if conditions.iter().all(|c| eval_condition(c, ctx)) {
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
