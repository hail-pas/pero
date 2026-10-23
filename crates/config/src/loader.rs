use crate::{blocks::COMMON_ENV_LIST_PARSE_KEYS, mode::RunMode};
use config_rs::{Config, Environment, File};
use pero_validate_core::{
    Validatable, ValidationError, ValidationErrorKind, ValidationLocation, ValidationReport,
    ValidationResult, ValidationSource,
};
use serde::de::DeserializeOwned;
use std::{
    path::{Path, PathBuf},
    str::FromStr,
};

pub const DEFAULT_CONFIG_DIR: &str = "config";
pub const DEFAULT_ENV_PREFIX: &str = "PERO";
pub const DEFAULT_RUN_MODE_ENV: &str = "PERO_RUN_MODE";
pub const DEFAULT_RUN_MODE: RunMode = RunMode::Local;

pub trait ParseConfigurable: Validatable + DeserializeOwned {
    fn env_list_parse_keys() -> &'static [&'static str] {
        &[]
    }
}

fn config_error(err: config_rs::ConfigError) -> ValidationError {
    ValidationError::new(
        ValidationErrorKind::MalformedInput,
        "Failed to load config",
        ValidationReport::new(ValidationSource::new(ValidationLocation::Config)),
    )
    .with_detail(err.to_string())
}

#[derive(Debug, Clone)]
pub struct ConfigLoader {
    config_dir: PathBuf,
    env_prefix: String,
    run_mode_env: String,
    run_mode: Option<RunMode>,
}

impl Default for ConfigLoader {
    fn default() -> Self {
        Self {
            config_dir: PathBuf::from(DEFAULT_CONFIG_DIR),
            env_prefix: DEFAULT_ENV_PREFIX.to_owned(),
            run_mode_env: DEFAULT_RUN_MODE_ENV.to_owned(),
            run_mode: None,
        }
    }
}

impl ConfigLoader {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn config_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.config_dir = dir.into();
        self
    }

    pub fn env_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.env_prefix = prefix.into();
        self
    }

    pub fn run_mode_env(mut self, key: impl Into<String>) -> Self {
        self.run_mode_env = key.into();
        self
    }

    pub fn run_mode(mut self, mode: RunMode) -> Self {
        self.run_mode = Some(mode);
        self
    }

    pub fn load<T>(self) -> ValidationResult<T>
    where
        T: ParseConfigurable,
    {
        let cfg = self
            .build_sources::<T>()?
            .build()
            .map_err(config_error)?
            .try_deserialize::<T>()
            .map_err(config_error)?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn build_sources<T>(
        &self,
    ) -> ValidationResult<config_rs::ConfigBuilder<config_rs::builder::DefaultState>>
    where
        T: ParseConfigurable,
    {
        let run_mode = self.resolve_run_mode()?;

        let default_file = self.config_dir.join("default.toml");
        let run_mode_file = self.config_dir.join(format!("{}.toml", run_mode.as_str()));

        if !default_file.exists() {
            return Err(ValidationError::new(
                ValidationErrorKind::RuleViolation,
                format!("missing required config file: {}", default_file.display()),
                ValidationReport::new(ValidationSource::new(ValidationLocation::Config)),
            ));
        }

        Ok(Config::builder()
            .add_source(File::from(default_file).required(true))
            .add_source(File::from(run_mode_file).required(false))
            .add_source(self.environment_source::<T>()))
    }

    fn resolve_run_mode(&self) -> ValidationResult<RunMode> {
        if let Some(mode) = &self.run_mode {
            return Ok(*mode);
        }

        let value =
            std::env::var(&self.run_mode_env).unwrap_or_else(|_| DEFAULT_RUN_MODE.to_string());
        RunMode::from_str(&value)
    }

    fn environment_source<T>(&self) -> Environment
    where
        T: ParseConfigurable,
    {
        let mut env = Environment::with_prefix(&self.env_prefix)
            .prefix_separator("__")
            .separator("__")
            .ignore_empty(true)
            .try_parsing(true)
            .list_separator(",");

        for key in COMMON_ENV_LIST_PARSE_KEYS
            .iter()
            .chain(T::env_list_parse_keys())
        {
            env = env.with_list_parse_key(key);
        }

        env
    }
}

pub fn load<T>() -> ValidationResult<T>
where
    T: ParseConfigurable,
{
    ConfigLoader::new().load::<T>()
}

pub fn load_from_dir<T>(dir: impl AsRef<Path>) -> ValidationResult<T>
where
    T: ParseConfigurable,
{
    ConfigLoader::new().config_dir(dir.as_ref()).load::<T>()
}
