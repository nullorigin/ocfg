pub mod commands;
pub mod config;
pub mod crypto;
pub mod dependencies;
pub mod error;
pub mod interactive;
pub mod json;
pub mod templates;
pub mod wiki_parser;

pub use error::{OcfgError, Result};
pub use json::{
    JsonValue, ToJson, FromJson,
    JsonObjectBuilder, JsonArrayBuilder,
    get_string_field, get_string_field_opt,
    get_bool_field, get_bool_field_opt,
    get_u32_field, get_u16_field,
    get_string_vec_field, get_string_vec_field_opt,
    get_object_field, get_object_field_opt,
    get_array_field, get_array_field_opt,
    get_string_field_or, get_bool_field_or,
    get_u32_field_or, get_u16_field_or,
    get_string_vec_field_or,
    FieldExtractor,
};

use config::OcfgConfig;

/// Initialize the configuration system
pub fn init() -> Result<OcfgConfig> {
    OcfgConfig::load().map_err(|e| err!(Config, "{}", e))
}

/// Get the default configuration
pub fn default_config() -> OcfgConfig {
    OcfgConfig::default()
}
