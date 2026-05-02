use crate::config::OcfgConfig;
use crate::templates::TemplateEngine;
use crate::error::Result;
use anyhow::Context;
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
            serde_json::to_string_pretty(&config)
                .context("Failed to serialize to JSON")?
        }
        "yaml" => {
            serde_yaml::to_string(&config)
                .context("Failed to serialize to YAML")?
        }
        "toml" => {
            toml::to_string_pretty(&config)
                .context("Failed to serialize to TOML")?
        }
        _ => {
            return Err(anyhow::anyhow!("Unsupported format: {}. Supported formats: env, json, yaml, toml", format).into());
        }
    };

    if let Some(output_path) = output {
        fs::write(&output_path, content)
            .context("Failed to write output file")?;
        println!("Configuration exported to: {}", output_path);
    } else {
        println!("{}", content);
    }

    Ok(())
}
