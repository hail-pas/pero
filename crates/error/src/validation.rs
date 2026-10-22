use crate::app::AppError;

impl From<pero_validate_core::ValidationReport> for AppError {
    fn from(report: pero_validate_core::ValidationReport) -> Self {
        AppError::validation_failed(report)
    }
}

impl From<pero_validate_core::ValidationError> for AppError {
    fn from(err: pero_validate_core::ValidationError) -> Self {
        let (kind, message, detail, report) = err.into_parts();

        match kind {
            pero_validate_core::ValidationErrorKind::MalformedInput => {
                let mut err = AppError::bad_request("malformed_input", message);
                if let Some(detail) = detail {
                    err = err.with_detail(detail);
                }
                err.with_validation_report(report)
            }
            pero_validate_core::ValidationErrorKind::RuleViolation
            | pero_validate_core::ValidationErrorKind::ConstraintViolation => {
                let mut err = AppError::validation_failed(report);
                if let Some(detail) = detail {
                    err = err.with_detail(detail);
                }
                err
            }
        }
    }
}
