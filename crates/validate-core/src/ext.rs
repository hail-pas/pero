use crate::{
    error::{ValidationError, ValidationResult},
    report::ValidationSource,
    traits::Validatable,
};

pub trait ValidateExt: Validatable + Sized {
    fn validated(self) -> ValidationResult<Self> {
        self.validate()?;
        Ok(self)
    }

    fn validated_with_source(self, source: ValidationSource) -> ValidationResult<Self> {
        self.validate()
            .map_err(|err: ValidationError| err.with_source(source))?;
        Ok(self)
    }
}

impl<T> ValidateExt for T where T: Validatable {}
