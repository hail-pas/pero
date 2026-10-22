use pero_validate_core::{Validatable, ValidationResult};
use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum SortDirection {
    Asc,
    #[default]
    Desc,
}

impl SortDirection {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Asc => "asc",
            Self::Desc => "desc",
        }
    }
}

impl fmt::Display for SortDirection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for SortDirection {
    type Err = SortParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_ascii_lowercase().as_str() {
            "asc" => Ok(Self::Asc),
            "desc" => Ok(Self::Desc),
            _ => Err(SortParseError::InvalidDirection(value.to_owned())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SortField {
    pub field: String,

    #[serde(default)]
    pub direction: SortDirection,
}

impl SortField {
    pub fn new(field: impl Into<String>, direction: SortDirection) -> Self {
        Self {
            field: field.into(),
            direction,
        }
    }
}

impl Validatable for SortField {
    fn validate(&self) -> ValidationResult {
        pero_validate_core::treat_as_malformed_input(pero_validate_core::not_blank(
            &self.field,
            "$.field",
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SortRequest {
    #[serde(default)]
    pub fields: Vec<SortField>,
}

impl SortRequest {
    pub fn new(fields: Vec<SortField>) -> Self {
        Self { fields }
    }

    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }

    pub fn first(&self) -> Option<&SortField> {
        self.fields.first()
    }
}

impl Validatable for SortRequest {
    fn validate(&self) -> ValidationResult {
        pero_validate_core::treat_as_malformed_input((|| {
            for (index, field) in self.fields.iter().enumerate() {
                pero_validate_core::not_blank(&field.field, &format!("$.fields[{index}].field"))?;
            }
            Ok(())
        })())
    }
}

impl FromStr for SortRequest {
    type Err = SortParseError;

    /// 支持格式：
    /// - created_at:desc
    /// - created_at:desc,name:asc
    /// - -created_at,name
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.trim().is_empty() {
            return Ok(Self::default());
        }

        let mut fields = Vec::new();

        for raw in value.split(',') {
            let raw = raw.trim();

            if raw.is_empty() {
                continue;
            }

            if let Some(field) = raw.strip_prefix('-') {
                fields.push(SortField::new(field, SortDirection::Desc));
                continue;
            }

            if let Some(field) = raw.strip_prefix('+') {
                fields.push(SortField::new(field, SortDirection::Asc));
                continue;
            }

            let mut parts = raw.splitn(2, ':');
            let field = parts
                .next()
                .ok_or_else(|| SortParseError::InvalidField(raw.to_owned()))?;

            let direction = match parts.next() {
                Some(direction) => direction.parse()?,
                None => SortDirection::Asc,
            };

            if field.trim().is_empty() {
                return Err(SortParseError::InvalidField(raw.to_owned()));
            }

            fields.push(SortField::new(field.trim(), direction));
        }

        Ok(Self { fields })
    }
}

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum SortParseError {
    #[error("invalid sort direction: {0}")]
    InvalidDirection(String),

    #[error("invalid sort field: {0}")]
    InvalidField(String),
}
