use pero_validate_core::{
    ContextualValidator, ValidationError, ValidationIssue, ValidationReport, ValidationResult,
    Validator,
};

#[derive(Debug, Clone, Copy, Default)]
pub struct ValidatorBridge;

impl<T> Validator<T> for ValidatorBridge
where
    T: validator::Validate,
{
    fn validate(&self, value: &T) -> ValidationResult {
        validator::Validate::validate(value).map_err(from_validator_errors)
    }
}

impl<T, C> ContextualValidator<T, C> for ValidatorBridge
where
    T: validator::Validate,
{
    fn validate_with(&self, value: &T, _ctx: &C) -> ValidationResult {
        validator::Validate::validate(value).map_err(from_validator_errors)
    }
}

pub fn from_validator_errors(errors: validator::ValidationErrors) -> ValidationError {
    let mut report = ValidationReport::unknown();

    for (field, field_errors) in errors.field_errors() {
        for error in field_errors {
            report.push(ValidationIssue::new(
                format!("$.{field}"),
                error.code.to_string(),
                error.to_string(),
            ));
        }
    }

    ValidationError::rule_violation(report)
}
