use std::time::Duration;

use pero_types::PgUrl;
use pero_validate_core::{
    Validatable, ValidationError, ValidationIssue, ValidationReport, ValidationResult,
};
use sea_orm::{ConnectOptions, Database, DatabaseConnection};
use serde::Deserialize;

use crate::guard::DatabaseGuard;

#[derive(Debug, Clone, Default, Deserialize)]
pub struct EmptyExtras {}

#[derive(Debug, Clone, Deserialize)]
#[serde(bound(deserialize = "E: Deserialize<'de>"))]
pub struct DatabaseConfig<E: Clone + Send + Sync + 'static = EmptyExtras> {
    pub url: PgUrl,
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,
    #[serde(default)]
    pub min_connections: u32,
    #[serde(default = "default_acquire_timeout_secs")]
    pub acquire_timeout_secs: u64,
    #[serde(default = "default_idle_timeout_secs")]
    pub idle_timeout_secs: Option<u64>,
    #[serde(default = "default_max_lifetime_secs")]
    pub max_lifetime_secs: Option<u64>,
    #[serde(flatten)]
    pub extras: E,
}

impl<E: Clone + Send + Sync + 'static> Validatable for DatabaseConfig<E> {
    fn validate(&self) -> ValidationResult {
        pero_validate_core::min(self.max_connections, 1, "database.max_connections")?;
        pero_validate_core::ensure(
            self.min_connections <= self.max_connections,
            "database.min_connections",
            "range",
            "database.min_connections cannot be greater than database.max_connections",
        )?;
        pero_validate_core::min(
            self.acquire_timeout_secs,
            1,
            "database.acquire_timeout_secs",
        )?;

        Ok(())
    }
}

impl<E: Clone + Send + Sync + 'static> DatabaseConfig<E> {
    pub async fn connect<F>(
        &self,
        hook: F,
    ) -> Result<(DatabaseConnection, DatabaseGuard), ValidationError>
    where
        F: FnOnce(&mut ConnectOptions, &E),
    {
        let mut opt = ConnectOptions::new(self.url.expose_secret().to_owned());
        opt.max_connections(self.max_connections)
            .min_connections(self.min_connections)
            .connect_timeout(Duration::from_secs(self.acquire_timeout_secs))
            .idle_timeout(self.idle_timeout_secs.map(Duration::from_secs))
            .max_lifetime(self.max_lifetime_secs.map(Duration::from_secs));

        hook(&mut opt, &self.extras);

        let db = Database::connect(opt).await.map_err(|source| {
            ValidationError::rule_violation(ValidationReport::config().with_issue(
                ValidationIssue::new("database.url", "connection_failed", source.to_string()),
            ))
        })?;

        tracing::info!(
            url = %self.url,
            max_connections = self.max_connections,
            min_connections = self.min_connections,
            "database pool initialized"
        );

        let guard = DatabaseGuard::new(db.clone());

        Ok((db, guard))
    }
}

fn default_max_connections() -> u32 {
    10
}

fn default_acquire_timeout_secs() -> u64 {
    10
}

fn default_idle_timeout_secs() -> Option<u64> {
    Some(600)
}

fn default_max_lifetime_secs() -> Option<u64> {
    Some(1800)
}
