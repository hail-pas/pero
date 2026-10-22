use std::path::PathBuf;

use pero_validate_core::{Validatable, ValidationResult};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AskamaConfig {
    pub static_dir: PathBuf,
    pub static_url_prefix: String,
}

impl Default for AskamaConfig {
    fn default() -> Self {
        Self {
            static_dir: PathBuf::from("ui/static"),
            static_url_prefix: "/static".to_owned(),
        }
    }
}

impl Validatable for AskamaConfig {
    fn validate(&self) -> ValidationResult {
        pero_validate_core::not_blank(self.static_url_prefix.as_str(), "askama.static_url_prefix")?;
        Ok(())
    }
}
