use crate::report::{ValidationReport, ValidationSource};
use serde::{Deserialize, Serialize};

pub type ValidationResult<T = ()> = Result<T, ValidationError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationErrorKind {
    MalformedInput,
    RuleViolation,
    ConstraintViolation,
}

impl ValidationErrorKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MalformedInput => "malformed_input",
            Self::RuleViolation => "rule_violation",
            Self::ConstraintViolation => "constraint_violation",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, thiserror::Error)]
#[error("{message}")]
pub struct ValidationError {
    kind: ValidationErrorKind,
    message: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,

    report: ValidationReport,
}

impl ValidationError {
    pub fn new(
        kind: ValidationErrorKind,
        message: impl Into<String>,
        report: ValidationReport,
    ) -> Self {
        Self {
            kind,
            message: message.into(),
            detail: None,
            report,
        }
    }

    pub fn rule_violation(report: ValidationReport) -> Self {
        Self::new(
            ValidationErrorKind::RuleViolation,
            "Validation failed",
            report,
        )
    }

    pub fn malformed_input(source: ValidationSource, detail: impl Into<String>) -> Self {
        Self::new(
            ValidationErrorKind::MalformedInput,
            "Malformed input",
            ValidationReport::new(source),
        )
        .with_detail(detail)
    }

    pub fn kind(&self) -> ValidationErrorKind {
        self.kind
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    pub fn detail(&self) -> Option<&str> {
        self.detail.as_deref()
    }

    pub fn report(&self) -> &ValidationReport {
        &self.report
    }

    pub fn into_parts(
        self,
    ) -> (
        ValidationErrorKind,
        String,
        Option<String>,
        ValidationReport,
    ) {
        (self.kind, self.message, self.detail, self.report)
    }

    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    pub fn with_source(mut self, source: ValidationSource) -> Self {
        self.report.source = source;
        self
    }
}

impl From<ValidationReport> for ValidationError {
    fn from(value: ValidationReport) -> Self {
        Self::rule_violation(value)
    }
}
