use crate::{kind::ErrorKind, problem::ProblemDetails};
use http::StatusCode;
use pero_validate_core::{ValidationIssue, ValidationReport};
use serde_json::Value;
use std::{collections::BTreeMap, error::Error, fmt};

pub type BoxError = Box<dyn Error + Send + Sync + 'static>;

#[derive(Debug)]
pub(crate) struct AppErrorInner {
    pub(crate) kind: ErrorKind,
    pub(crate) code: String,
    pub(crate) message: String,
    pub(crate) detail: Option<String>,
    pub(crate) instance: Option<String>,
    pub(crate) request_id: Option<String>,
    pub(crate) validation: Option<ValidationReport>,
    pub(crate) numeric_code: Option<u32>,
    pub(crate) extensions: BTreeMap<String, Value>,
    pub(crate) source: Option<BoxError>,
}

impl AppErrorInner {
    fn new(kind: ErrorKind, code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            kind,
            code: code.into(),
            message: message.into(),
            detail: None,
            instance: None,
            request_id: None,
            validation: None,
            numeric_code: None,
            extensions: BTreeMap::new(),
            source: None,
        }
    }
}

#[derive(Debug)]
pub struct AppError {
    pub(crate) inner: Box<AppErrorInner>,
}

impl AppError {
    #[must_use]
    pub fn new(kind: ErrorKind, code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            inner: Box::new(AppErrorInner::new(kind, code, message)),
        }
    }

    #[must_use]
    pub fn bad_request(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(ErrorKind::BadRequest, code, message)
    }

    #[must_use]
    pub fn unauthorized(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Unauthorized, code, message)
    }

    #[must_use]
    pub fn forbidden(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Forbidden, code, message)
    }

    #[must_use]
    pub fn not_found(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(ErrorKind::NotFound, code, message)
    }

    #[must_use]
    pub fn conflict(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Conflict, code, message)
    }

    #[must_use]
    pub fn validation_failed(report: ValidationReport) -> Self {
        Self::new(
            ErrorKind::UnprocessableEntity,
            "validation_failed",
            "Validation failed",
        )
        .with_validation_report(report)
    }

    #[must_use]
    pub fn dependency_failure(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(ErrorKind::DependencyFailure, code, message)
    }

    #[must_use]
    pub fn internal(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Internal, code, message)
    }

    #[inline]
    #[must_use]
    pub fn kind(&self) -> ErrorKind {
        self.inner.kind
    }

    #[inline]
    #[must_use]
    pub fn code(&self) -> &str {
        self.inner.code.as_str()
    }

    #[inline]
    #[must_use]
    pub fn message(&self) -> &str {
        self.inner.message.as_str()
    }

    #[inline]
    #[must_use]
    pub fn detail(&self) -> Option<&str> {
        self.inner.detail.as_deref()
    }

    #[inline]
    #[must_use]
    pub fn instance(&self) -> Option<&str> {
        self.inner.instance.as_deref()
    }

    #[inline]
    #[must_use]
    pub fn request_id(&self) -> Option<&str> {
        self.inner.request_id.as_deref()
    }

    #[inline]
    #[must_use]
    pub fn validation_report(&self) -> Option<&ValidationReport> {
        self.inner.validation.as_ref()
    }

    #[inline]
    #[must_use]
    pub fn errors(&self) -> &[ValidationIssue] {
        match self.inner.validation.as_ref() {
            Some(report) => report.issues.as_slice(),
            None => &[],
        }
    }

    #[inline]
    #[must_use]
    pub fn extensions(&self) -> &BTreeMap<String, Value> {
        &self.inner.extensions
    }

    #[inline]
    #[must_use]
    pub fn status_code(&self) -> StatusCode {
        self.inner.kind.status_code()
    }

    #[inline]
    #[must_use]
    pub fn numeric_code(&self) -> u32 {
        self.inner
            .numeric_code
            .unwrap_or_else(|| self.inner.kind.default_numeric_code())
    }

    #[must_use]
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.inner.detail = Some(detail.into());
        self
    }

    #[must_use]
    pub fn with_instance(mut self, instance: impl Into<String>) -> Self {
        self.inner.instance = Some(instance.into());
        self
    }

    #[must_use]
    pub fn with_request_id(mut self, request_id: impl Into<String>) -> Self {
        self.inner.request_id = Some(request_id.into());
        self
    }

    #[must_use]
    pub fn with_validation_report(mut self, report: ValidationReport) -> Self {
        self.inner.validation = Some(report);
        self
    }

    #[must_use]
    pub fn with_numeric_code(mut self, code: u32) -> Self {
        self.inner.numeric_code = Some(code);
        self
    }

    #[must_use]
    pub fn with_extension(mut self, key: impl Into<String>, value: impl Into<Value>) -> Self {
        self.inner.extensions.insert(key.into(), value.into());
        self
    }

    #[must_use]
    pub fn with_source<E>(mut self, source: E) -> Self
    where
        E: Error + Send + Sync + 'static,
    {
        self.inner.source = Some(Box::new(source));
        self
    }

    #[must_use]
    pub fn into_problem(self) -> ProblemDetails {
        ProblemDetails::from_app_error_into(self)
    }

    #[must_use]
    pub fn to_problem(&self) -> ProblemDetails {
        ProblemDetails::from_app_error(self)
    }
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.inner.code.as_str())?;
        f.write_str(": ")?;
        f.write_str(self.inner.message.as_str())?;

        if let Some(detail) = self.inner.detail.as_deref() {
            write!(f, " — {detail}")?;
        }

        let mut source = self
            .inner
            .source
            .as_deref()
            .map(|err| err as &(dyn Error + 'static));

        while let Some(err) = source {
            write!(f, " → {err}")?;
            source = err.source();
        }

        Ok(())
    }
}

impl Error for AppError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.inner
            .source
            .as_deref()
            .map(|err| err as &(dyn Error + 'static))
    }
}

// Json
impl AppError {
    #[must_use]
    pub fn json_internal(
        code: impl Into<String>,
        message: impl Into<String>,
        err: serde_json::Error,
    ) -> Self {
        Self::attach_json_error_metadata(Self::internal(code, message), err)
    }

    #[must_use]
    pub fn json_bad_request(
        code: impl Into<String>,
        message: impl Into<String>,
        err: serde_json::Error,
    ) -> Self {
        Self::attach_json_error_metadata(Self::bad_request(code, message), err)
    }

    #[must_use]
    pub fn json_dependency_failure(
        code: impl Into<String>,
        message: impl Into<String>,
        err: serde_json::Error,
    ) -> Self {
        Self::attach_json_error_metadata(Self::dependency_failure(code, message), err)
    }

    fn attach_json_error_metadata(base: Self, err: serde_json::Error) -> Self {
        let category = match err.classify() {
            serde_json::error::Category::Io => "io",
            serde_json::error::Category::Syntax => "syntax",
            serde_json::error::Category::Data => "data",
            serde_json::error::Category::Eof => "eof",
        };

        let line = err.line() as u64;
        let column = err.column() as u64;
        let detail = err.to_string();

        base.with_detail(detail)
            .with_extension("source", "serde_json")
            .with_extension("category", category)
            .with_extension("line", line)
            .with_extension("column", column)
            .with_source(err)
    }
}

impl From<serde_json::Error> for AppError {
    fn from(err: serde_json::Error) -> Self {
        Self::json_internal(
            "json_codec_error",
            "JSON serialization or deserialization failed",
            err,
        )
    }
}
