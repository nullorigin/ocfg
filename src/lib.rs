pub mod commands;
pub mod config;
pub mod crypto;
pub mod dependencies;
pub mod error;
pub mod interactive;
pub mod templates;
pub mod wiki_parser;

pub use error::{OcfgError, Result};

use config::OcfgConfig;

/// Initialize the configuration system
pub fn init() -> Result<OcfgConfig> {
    OcfgConfig::load().map_err(|e| OcfgError::Config(e.to_string()))
}

/// Get the default configuration
pub fn default_config() -> OcfgConfig {
    OcfgConfig::default()
}
