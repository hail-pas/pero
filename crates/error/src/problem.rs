use crate::app::AppError;
use pero_validate_core::{ValidationIssue, ValidationReport};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProblemType(String);

impl ProblemType {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn about_blank() -> Self {
        Self("about:blank".to_owned())
    }

    pub fn app(code: &str) -> Self {
        Self(format!("https://errors.pero.dev/problems/{code}"))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Serialize for ProblemType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for ProblemType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(Self(String::deserialize(deserializer)?))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProblemDetails {
    #[serde(rename = "type")]
    pub type_uri: ProblemType,

    pub title: String,

    pub status: u16,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<ValidationIssue>,

    #[serde(flatten)]
    pub extensions: BTreeMap<String, Value>,
}

impl ProblemDetails {
    pub fn from_app_error(err: &AppError) -> Self {
        let mut extensions = err.extensions().clone();
        if let Some(report) = err.validation_report() {
            add_validation_source(&mut extensions, report);
        }

        Self {
            type_uri: ProblemType::app(err.code()),
            title: err.message().to_owned(),
            status: err.status_code().as_u16(),
            detail: err.detail().map(str::to_owned),
            instance: err.instance().map(str::to_owned),
            code: Some(err.code().to_owned()),
            request_id: err.request_id().map(str::to_owned),
            errors: err.errors().to_vec(),
            extensions,
        }
    }

    pub fn from_app_error_into(err: AppError) -> Self {
        let inner = *err.inner;
        let type_uri = ProblemType::app(&inner.code);
        let status = inner.kind.status_code().as_u16();
        let mut extensions = inner.extensions;
        let errors = inner
            .validation
            .as_ref()
            .map(|report| {
                add_validation_source(&mut extensions, report);
                report.issues.clone()
            })
            .unwrap_or_default();

        Self {
            type_uri,
            status,
            title: inner.message,
            detail: inner.detail,
            instance: inner.instance,
            code: Some(inner.code),
            request_id: inner.request_id,
            errors,
            extensions,
        }
    }

    pub fn internal_server_error() -> Self {
        Self {
            type_uri: ProblemType::app("internal_server_error"),
            title: "Internal Server Error".to_owned(),
            status: 500,
            detail: None,
            instance: None,
            code: Some("internal_server_error".to_owned()),
            request_id: None,
            errors: Vec::new(),
            extensions: BTreeMap::new(),
        }
    }
}

fn add_validation_source(extensions: &mut BTreeMap<String, Value>, report: &ValidationReport) {
    if let Ok(source) = serde_json::to_value(&report.source) {
        extensions.insert("validation_source".to_owned(), source);
    }
}
