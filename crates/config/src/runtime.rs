use std::path::PathBuf;

use pero_validate_core::{Validatable, ValidationResult, ensure};

#[derive(Debug, Clone)]
pub struct RuntimeOption {
    pub config_dir: PathBuf,
}

impl Default for RuntimeOption {
    fn default() -> Self {
        Self {
            config_dir: PathBuf::from("config"),
        }
    }
}

impl Validatable for RuntimeOption {
    fn validate(&self) -> ValidationResult {
        ensure(
            !self.config_dir.as_os_str().is_empty(),
            "config_dir",
            "required",
            "config_dir must not be empty",
        )?;
        ensure(
            self.config_dir.is_dir(),
            "config_dir",
            "not_found",
            format!(
                "config directory does not exist: {}",
                self.config_dir.display()
            ),
        )?;
        Ok(())
    }
}
