use crate::error::ValidationResult;

pub trait Validatable {
    fn validate(&self) -> ValidationResult;
}

pub trait ValidatableWith<C> {
    fn validate_with(&self, ctx: &C) -> ValidationResult;
}

pub trait Validator<T> {
    fn validate(&self, value: &T) -> ValidationResult;
}

pub trait ContextualValidator<T, C> {
    fn validate_with(&self, value: &T, ctx: &C) -> ValidationResult;
}
