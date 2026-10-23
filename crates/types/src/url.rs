use ::url::Url;
use pero_validate_core::{
    Validatable, ValidationError, ValidationIssue, ValidationReport, ValidationResult,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{fmt, marker::PhantomData, str::FromStr};

const REDACTED_PASSWORD: &str = "********";

pub trait TypedUrlSpec {
    const TYPE_NAME: &'static str;
    const ALLOWED_SCHEMES: &'static [&'static str];
}

pub struct TypedUrl<S>
where
    S: TypedUrlSpec,
{
    url: Url,
    _spec: PhantomData<S>,
}

impl<S> TypedUrl<S>
where
    S: TypedUrlSpec,
{
    pub fn parse(value: &str) -> ValidationResult<Self> {
        Self::parse_at(value, "$")
    }

    pub fn parse_at(value: &str, path: &str) -> ValidationResult<Self> {
        parse_url(value, path, S::ALLOWED_SCHEMES).map(|url| Self {
            url,
            _spec: PhantomData,
        })
    }

    pub fn expose_secret(&self) -> &str {
        self.url.as_str()
    }

    pub fn redacted(&self) -> String {
        redact_url(&self.url)
    }
}

impl<S> Clone for TypedUrl<S>
where
    S: TypedUrlSpec,
{
    fn clone(&self) -> Self {
        Self {
            url: self.url.clone(),
            _spec: PhantomData,
        }
    }
}

impl<S> PartialEq for TypedUrl<S>
where
    S: TypedUrlSpec,
{
    fn eq(&self, other: &Self) -> bool {
        self.url == other.url
    }
}

impl<S> Eq for TypedUrl<S> where S: TypedUrlSpec {}

impl<S> std::hash::Hash for TypedUrl<S>
where
    S: TypedUrlSpec,
{
    fn hash<H>(&self, state: &mut H)
    where
        H: std::hash::Hasher,
    {
        self.url.hash(state);
    }
}

impl<S> fmt::Debug for TypedUrl<S>
where
    S: TypedUrlSpec,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple(S::TYPE_NAME).field(&self.redacted()).finish()
    }
}

impl<S> fmt::Display for TypedUrl<S>
where
    S: TypedUrlSpec,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.redacted())
    }
}

impl<S> Serialize for TypedUrl<S>
where
    S: TypedUrlSpec,
{
    fn serialize<T>(&self, serializer: T) -> Result<T::Ok, T::Error>
    where
        T: Serializer,
    {
        serializer.serialize_str(&self.redacted())
    }
}

impl<'de, S> Deserialize<'de> for TypedUrl<S>
where
    S: TypedUrlSpec,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(serde::de::Error::custom)
    }
}

impl<S> FromStr for TypedUrl<S>
where
    S: TypedUrlSpec,
{
    type Err = ValidationError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl<S> Validatable for TypedUrl<S>
where
    S: TypedUrlSpec,
{
    fn validate(&self) -> ValidationResult {
        if S::ALLOWED_SCHEMES
            .iter()
            .any(|scheme| *scheme == self.url.scheme())
        {
            return Ok(());
        }

        Err(ValidationError::rule_violation(
            ValidationReport::unknown().with_issue(
                ValidationIssue::new("$", "scheme", "URL scheme is not allowed")
                    .with_param("actual", self.url.scheme().to_owned())
                    .with_param("allowed", S::ALLOWED_SCHEMES.to_vec()),
            ),
        ))
    }
}

pub enum PgUrlSpec {}

impl TypedUrlSpec for PgUrlSpec {
    const TYPE_NAME: &'static str = "PgUrl";
    const ALLOWED_SCHEMES: &'static [&'static str] = &["postgres", "postgresql"];
}

pub type PgUrl = TypedUrl<PgUrlSpec>;

pub enum RedisUrlSpec {}

impl TypedUrlSpec for RedisUrlSpec {
    const TYPE_NAME: &'static str = "RedisUrl";
    const ALLOWED_SCHEMES: &'static [&'static str] = &["redis", "rediss"];
}

pub type RedisUrl = TypedUrl<RedisUrlSpec>;

fn parse_url(value: &str, path: &str, allowed_schemes: &[&str]) -> ValidationResult<Url> {
    pero_validate_core::not_blank(value, path)?;

    let url = Url::parse(value).map_err(|err| {
        ValidationError::rule_violation(
            ValidationReport::unknown().with_issue(
                ValidationIssue::new(path, "format", "must be a valid absolute URL")
                    .with_param("format", "url")
                    .with_param("reason", err.to_string()),
            ),
        )
    })?;

    if allowed_schemes.iter().any(|scheme| *scheme == url.scheme()) {
        return Ok(url);
    }

    Err(ValidationError::rule_violation(
        ValidationReport::unknown().with_issue(
            ValidationIssue::new(path, "scheme", "URL scheme is not allowed")
                .with_param("actual", url.scheme().to_owned())
                .with_param("allowed", allowed_schemes.to_vec()),
        ),
    ))
}

fn redact_url(url: &Url) -> String {
    let mut redacted = url.clone();

    if redacted.password().is_some() {
        let _ = redacted.set_password(Some(REDACTED_PASSWORD));
    }

    redacted.to_string()
}
