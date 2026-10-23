use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::BTreeMap, fmt};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ValidationLocation {
    Body,
    Query,
    Path,
    Header,
    Cookie,
    Config,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationSource {
    pub location: ValidationLocation,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

impl ValidationSource {
    pub fn new(location: ValidationLocation) -> Self {
        Self {
            location,
            name: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ValidationCode(String);

impl ValidationCode {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ValidationCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<&str> for ValidationCode {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

impl From<String> for ValidationCode {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ValidationIssue {
    /// Stable field path used by logs and clients, for example `$.user.email`.
    pub path: String,

    /// RFC 6901 JSON Pointer derived from `path` where possible.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pointer: Option<String>,

    /// Stable machine-readable validation code.
    pub code: ValidationCode,

    /// Default developer-facing message.
    pub message: String,

    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub params: BTreeMap<String, Value>,
}

impl ValidationIssue {
    pub fn new(
        path: impl Into<String>,
        code: impl Into<ValidationCode>,
        message: impl Into<String>,
    ) -> Self {
        let path = path.into();
        Self {
            pointer: Some(path_to_json_pointer(&path)),
            path,
            code: code.into(),
            message: message.into(),
            params: BTreeMap::new(),
        }
    }

    pub fn with_param(mut self, key: impl Into<String>, value: impl Into<Value>) -> Self {
        self.params.insert(key.into(), value.into());
        self
    }
}

pub fn path_to_json_pointer(path: &str) -> String {
    let path = path.trim();

    if path.is_empty() || path == "$" {
        return String::new();
    }

    let path = path.strip_prefix('$').unwrap_or(path);
    let path = path.strip_prefix('.').unwrap_or(path);

    if path.is_empty() {
        return String::new();
    }

    let mut out = String::new();
    let mut token = String::new();

    for ch in path.chars() {
        match ch {
            '.' | '[' | ']' => {
                if !token.is_empty() {
                    out.push('/');
                    out.push_str(&escape_json_pointer_token(&token));
                    token.clear();
                }
            }
            _ => token.push(ch),
        }
    }

    if !token.is_empty() {
        out.push('/');
        out.push_str(&escape_json_pointer_token(&token));
    }

    out
}

fn escape_json_pointer_token(value: &str) -> String {
    value.replace('~', "~0").replace('/', "~1")
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ValidationReport {
    pub source: ValidationSource,

    #[serde(default)]
    pub issues: Vec<ValidationIssue>,
}

impl ValidationReport {
    pub fn new(source: ValidationSource) -> Self {
        Self {
            source,
            issues: Vec::new(),
        }
    }

    pub fn unknown() -> Self {
        Self::new(ValidationSource::new(ValidationLocation::Unknown))
    }

    pub fn body() -> Self {
        Self::new(ValidationSource::new(ValidationLocation::Body))
    }

    pub fn query() -> Self {
        Self::new(ValidationSource::new(ValidationLocation::Query))
    }

    pub fn path() -> Self {
        Self::new(ValidationSource::new(ValidationLocation::Path))
    }

    pub fn config() -> Self {
        Self::new(ValidationSource::new(ValidationLocation::Config))
    }

    pub fn push(&mut self, issue: ValidationIssue) {
        self.issues.push(issue);
    }

    pub fn is_empty(&self) -> bool {
        self.issues.is_empty()
    }

    pub fn with_source(mut self, source: ValidationSource) -> Self {
        self.source = source;
        self
    }

    pub fn with_issue(mut self, issue: ValidationIssue) -> Self {
        self.push(issue);
        self
    }
}
