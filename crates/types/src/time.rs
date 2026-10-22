use pero_validate_core::{Validatable, ValidationResult};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Timestamp(OffsetDateTime);

impl Timestamp {
    pub fn now_utc() -> Self {
        Self(OffsetDateTime::now_utc())
    }

    pub fn from_offset_datetime(value: OffsetDateTime) -> Self {
        Self(value)
    }

    pub fn into_offset_datetime(self) -> OffsetDateTime {
        self.0
    }

    pub fn as_offset_datetime(&self) -> &OffsetDateTime {
        &self.0
    }

    pub fn unix_timestamp(self) -> i64 {
        self.0.unix_timestamp()
    }
}

impl From<OffsetDateTime> for Timestamp {
    fn from(value: OffsetDateTime) -> Self {
        Self(value)
    }
}

impl From<Timestamp> for OffsetDateTime {
    fn from(value: Timestamp) -> Self {
        value.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DateTimeRange {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start: Option<Timestamp>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub end: Option<Timestamp>,
}

impl DateTimeRange {
    pub fn new(start: Option<Timestamp>, end: Option<Timestamp>) -> Self {
        Self { start, end }
    }

    pub fn empty() -> Self {
        Self {
            start: None,
            end: None,
        }
    }

    pub fn contains(&self, value: Timestamp) -> bool {
        if let Some(start) = self.start
            && value < start
        {
            return false;
        }

        if let Some(end) = self.end
            && value > end
        {
            return false;
        }

        true
    }

    pub fn is_valid(&self) -> bool {
        match (self.start, self.end) {
            (Some(start), Some(end)) => start <= end,
            _ => true,
        }
    }
}

impl Default for DateTimeRange {
    fn default() -> Self {
        Self::empty()
    }
}

impl Validatable for DateTimeRange {
    fn validate(&self) -> ValidationResult {
        pero_validate_core::ensure(
            self.is_valid(),
            "$",
            "range",
            "start must be earlier than or equal to end",
        )
    }
}
