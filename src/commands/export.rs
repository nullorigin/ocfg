use crate::config::OcfgConfig;
use crate::templates::TemplateEngine;
use crate::error::Result;
use crate::err;
use crate::json::ToJson;
use std::fs;

pub async fn run(format: String, output: Option<String>) -> Result<()> {
    println!("Exporting configuration...");

    let config = OcfgConfig::load()?;
    let templates = TemplateEngine::new()?;

    let content = match format.as_str() {
        "env" => {
            let config_env = templates.render_setup_config_env(&config)?;
            let secrets_env = templates.render_setup_secrets_env(&config)?;
            format!("{}\n\n# Secrets file (setup-secrets.env)\n{}", config_env, secrets_env)
        }
        "json" => {
            config.to_json_pretty(2)
        }
        "toml" => {
            toml::to_string_pretty(&config)
                .map_err(|e| err!(Serialization, "Failed to serialize to TOML: {}", e))?
        }
        _ => {
            return Err(err!(Validation, "Unsupported format: {}. Supported formats: env, json, yaml, toml", format));
        }
    };

    if let Some(output_path) = output {
        fs::write(&output_path, content)
            .map_err(|e| crate::error::OcfgError::Io(e))?;
        println!("Configuration exported to: {}", output_path);
    } else {
        println!("{}", content);
    }

    Ok(())
}
