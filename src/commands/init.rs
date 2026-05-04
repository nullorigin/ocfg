use crate::config::OcfgConfig;
use crate::error::Result;
use crate::err;
use crate::interactive;

pub async fn run(profile: Option<String>, target: Option<String>, non_interactive: bool) -> Result<()> {
    println!("Initializing OpenWrt configuration...");

    if let Some(profile) = profile {
        println!("Using profile: {}", profile);
    }

    if let Some(target) = target {
        println!("Target device: {}", target);
    }

    let config = if non_interactive {
        println!("Running in non-interactive mode with defaults...");
        let mut config = OcfgConfig::default();
        
        // Allow setting crypto library via environment variable
        if let Ok(crypto_lib) = std::env::var("OCFG_CRYPTO_LIBRARY") {
            config.build.crypto_library = crypto_lib.parse()
                .unwrap_or(crate::config::CryptoLibrary::OpenSSL);
            println!("Using crypto library from environment: {}", config.build.crypto_library);
        }
        
        config
    } else {
        interactive::interactive_wizard()?
    };

    config.save()
        .map_err(|e| err!(Config, "Failed to save configuration: {}", e))?;

    println!("\nConfiguration initialized successfully!");
    println!("Config file saved to: {:?}", OcfgConfig::config_path());

    Ok(())
}
