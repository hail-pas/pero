use pero_validate_core::{Validatable, ValidationResult};
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct I18nConfig {
    pub default_locale: String,
    pub available_locales: Vec<String>,
    pub fallback_locale: String,
    pub dir: PathBuf,
}

impl Default for I18nConfig {
    fn default() -> Self {
        Self {
            default_locale: "en".to_owned(),
            available_locales: vec!["en".to_owned()],
            fallback_locale: "en".to_owned(),
            dir: PathBuf::from("locales"),
        }
    }
}

impl I18nConfig {
    pub fn init(&self) {
        if let Some(dir) = self.dir.to_str() {
            let _ = rust_i18n::try_load_locales(dir, |_| false, false);
        }
        rust_i18n::set_locale(&self.default_locale);
    }
}

impl Validatable for I18nConfig {
    fn validate(&self) -> ValidationResult {
        pero_validate_core::not_blank(&self.default_locale, "i18n.default_locale")?;
        pero_validate_core::not_blank(&self.fallback_locale, "i18n.fallback_locale")?;

        pero_validate_core::ensure(
            !self.available_locales.is_empty(),
            "i18n.available_locales",
            "empty",
            "available_locales must not be empty",
        )?;

        pero_validate_core::ensure(
            self.available_locales
                .iter()
                .any(|l| l == &self.default_locale),
            "i18n.default_locale",
            "invalid",
            "default_locale must be in available_locales",
        )?;

        pero_validate_core::ensure(
            self.available_locales
                .iter()
                .any(|l| l == &self.fallback_locale),
            "i18n.fallback_locale",
            "invalid",
            "fallback_locale must be in available_locales",
        )?;

        Ok(())
    }
}
