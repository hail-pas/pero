use std::path::PathBuf;

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FrontendConfig {
    pub static_dir: PathBuf,
}

impl Default for FrontendConfig {
    fn default() -> Self {
        Self {
            static_dir: PathBuf::from("ui/static"),
        }
    }
}
