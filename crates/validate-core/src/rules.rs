use crate::{
    error::{ValidationError, ValidationResult},
    report::{ValidationCode, ValidationIssue, ValidationReport},
};
use serde::Serialize;
use serde_json::Value;
use std::fmt;

pub fn required<T>(value: Option<T>, path: &str) -> ValidationResult<T> {
    value.ok_or_else(|| failed(issue(path, "required", "is required")))
}

pub fn not_blank(value: &str, path: &str) -> ValidationResult {
    if value.trim().is_empty() {
        Err(failed(issue(path, "not_blank", "must not be blank")))
    } else {
        Ok(())
    }
}

pub fn min<T>(value: T, minimum: T, path: &str) -> ValidationResult
where
    T: Copy + PartialOrd + Serialize + fmt::Display,
{
    if value < minimum {
        Err(failed(
            issue(path, "min", format!("must be at least {minimum}"))
                .with_param("min", to_value(minimum))
                .with_param("actual", to_value(value)),
        ))
    } else {
        Ok(())
    }
}

pub fn max<T>(value: T, maximum: T, path: &str) -> ValidationResult
where
    T: Copy + PartialOrd + Serialize + fmt::Display,
{
    if value > maximum {
        Err(failed(
            issue(path, "max", format!("must be at most {maximum}"))
                .with_param("max", to_value(maximum))
                .with_param("actual", to_value(value)),
        ))
    } else {
        Ok(())
    }
}

pub fn range<T>(value: T, minimum: T, maximum: T, path: &str) -> ValidationResult
where
    T: Copy + PartialOrd + Serialize + fmt::Display,
{
    if value < minimum || value > maximum {
        Err(failed(
            issue(
                path,
                "range",
                format!("must be between {minimum} and {maximum}"),
            )
            .with_param("min", to_value(minimum))
            .with_param("max", to_value(maximum))
            .with_param("actual", to_value(value)),
        ))
    } else {
        Ok(())
    }
}

pub fn min_length(value: &str, minimum: usize, path: &str) -> ValidationResult {
    let actual = value.chars().count();

    if actual < minimum {
        Err(failed(
            issue(
                path,
                "min_length",
                format!("length must be at least {minimum}"),
            )
            .with_param("min", minimum as u64)
            .with_param("actual", actual as u64),
        ))
    } else {
        Ok(())
    }
}

pub fn max_length(value: &str, maximum: usize, path: &str) -> ValidationResult {
    let actual = value.chars().count();

    if actual > maximum {
        Err(failed(
            issue(
                path,
                "max_length",
                format!("length must be at most {maximum}"),
            )
            .with_param("max", maximum as u64)
            .with_param("actual", actual as u64),
        ))
    } else {
        Ok(())
    }
}

pub fn length_between(value: &str, minimum: usize, maximum: usize, path: &str) -> ValidationResult {
    let actual = value.chars().count();

    if actual < minimum || actual > maximum {
        Err(failed(
            issue(
                path,
                "length",
                format!("length must be between {minimum} and {maximum}"),
            )
            .with_param("min", minimum as u64)
            .with_param("max", maximum as u64)
            .with_param("actual", actual as u64),
        ))
    } else {
        Ok(())
    }
}

pub fn one_of<T>(value: &T, allowed: &[T], path: &str) -> ValidationResult
where
    T: PartialEq + Serialize + fmt::Display,
{
    if allowed.iter().any(|candidate| candidate == value) {
        return Ok(());
    }

    let allowed_text = allowed
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ");

    Err(failed(
        issue(path, "one_of", format!("must be one of: {allowed_text}"))
            .with_param("allowed", to_value(allowed))
            .with_param("actual", to_value(value)),
    ))
}

pub fn format(
    value: &str,
    path: &str,
    name: &str,
    predicate: impl FnOnce(&str) -> bool,
) -> ValidationResult {
    if predicate(value) {
        Ok(())
    } else {
        Err(failed(
            issue(path, "format", format!("must match {name} format"))
                .with_param("format", name.to_owned()),
        ))
    }
}

pub fn predicate(
    condition: bool,
    path: &str,
    code: impl Into<ValidationCode>,
    message: impl Into<String>,
) -> ValidationResult {
    if condition {
        Ok(())
    } else {
        Err(failed(issue(path, code, message)))
    }
}

pub fn ensure(
    condition: bool,
    path: &str,
    code: impl Into<ValidationCode>,
    message: impl Into<String>,
) -> ValidationResult {
    predicate(condition, path, code, message)
}

fn issue(
    path: impl Into<String>,
    code: impl Into<ValidationCode>,
    message: impl Into<String>,
) -> ValidationIssue {
    ValidationIssue::new(path, code, message)
}

fn failed(issue: ValidationIssue) -> ValidationError {
    ValidationError::rule_violation(ValidationReport::unknown().with_issue(issue))
}

fn to_value(value: impl Serialize) -> Value {
    serde_json::to_value(value).unwrap_or(Value::Null)
}
