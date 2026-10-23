use crate::error::ValidationResult;

pub trait Validatable {
    fn validate(&self) -> ValidationResult;
}
