use pero_validate_core::{Validatable, ValidationResult};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CookieConfig {
    pub domain: String,
    pub secure: bool,
    pub same_site: String,
    pub path: String,
}

impl Default for CookieConfig {
    fn default() -> Self {
        Self {
            domain: String::new(),
            secure: false,
            same_site: "Lax".to_owned(),
            path: "/".to_owned(),
        }
    }
}

impl Validatable for CookieConfig {
    fn validate(&self) -> ValidationResult {
        pero_validate_core::not_blank(&self.path, "cookie.path")?;
        pero_validate_core::one_of(
            &self.same_site,
            &["Lax".to_owned(), "Strict".to_owned(), "None".to_owned()],
            "cookie.same_site",
        )?;
        if self.same_site == "None" {
            pero_validate_core::ensure(
                self.secure,
                "cookie.secure",
                "invalid",
                "cookie.same_site=None requires cookie.secure=true",
            )?;
        }
        Ok(())
    }
}
