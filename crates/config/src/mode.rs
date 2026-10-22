use pero_validate_core::{
    ValidationError, ValidationErrorKind, ValidationLocation, ValidationReport, ValidationSource,
};
use serde::{Deserialize, Deserializer};
use std::{fmt, str::FromStr};

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RunMode {
    #[default]
    Local,
    Development,
    Test,
    Production,
}

impl RunMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Development => "development",
            Self::Test => "test",
            Self::Production => "production",
        }
    }
}

impl fmt::Display for RunMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for RunMode {
    type Err = ValidationError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        pero_validate_core::not_blank(value, "run_mode")?;

        match value {
            "local" => Ok(Self::Local),
            "development" => Ok(Self::Development),
            "test" => Ok(Self::Test),
            "production" => Ok(Self::Production),
            _ => Err(ValidationError::new(
                ValidationErrorKind::RuleViolation,
                format!(
                    "unsupported `{value}`; expected one of: local, development, test, production"
                ),
                ValidationReport::new(ValidationSource::new(ValidationLocation::Config)),
            )),
        }
    }
}

impl<'de> Deserialize<'de> for RunMode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::from_str(&value).map_err(serde::de::Error::custom)
    }
}
