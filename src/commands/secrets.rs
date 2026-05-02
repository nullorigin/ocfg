use crate::config::OcfgConfig;
use crate::crypto;
use crate::error::Result;
use std::fs;

pub async fn run(
    output: Option<String>,
    radius: bool,
    certificates: bool,
    vpn: bool,
    all: bool,
    _non_interactive: bool,
) -> Result<()> {
    println!("Generating secrets...");

    let mut config = OcfgConfig::load()?;

    let output_dir = output.unwrap_or_else(|| ".".to_string());

    if all || radius {
        println!("Generating RADIUS secrets...");
        config.secrets.radius_shared_secret = Some(crypto::generate_radius_secret()?);
        config.secrets.radius_admin_password = Some(crypto::generate_password(32)?);
        config.secrets.wifi_radius_secret = Some(crypto::generate_radius_secret()?);
        config.secrets.wired_radius_secret = Some(crypto::generate_radius_secret()?);
    }

    if all || certificates {
        println!("Generating certificate secrets...");
        config.secrets.ca_key_password = Some(crypto::generate_password(32)?);
        config.secrets.server_key_password = Some(crypto::generate_password(32)?);
    }

    if all || vpn {
        println!("Generating VPN secrets...");
        config.secrets.encryption_key = Some(crypto::generate_encryption_key()?);
        config.secrets.hmac_key = Some(crypto::generate_hmac_key()?);
        config.secrets.wifi_24g_password = Some(crypto::generate_password(24)?);
        config.secrets.wifi_5g_password = Some(crypto::generate_password(24)?);
    }

    if all {
        println!("Generating additional secrets...");
        config.secrets.ddns_api_key = Some(crypto::generate_api_key()?);
        config.secrets.cloudflare_api_token = Some(crypto::generate_api_key()?);
    }

    // Save secrets to separate file
    let secrets_path = if output_dir == "." {
        OcfgConfig::secrets_path()
    } else {
        std::path::PathBuf::from(&output_dir).join("secrets.toml")
    };

    let secrets_content = toml::to_string_pretty(&config.secrets)
        .map_err(|e| crate::error::OcfgError::serialization(format!("Failed to serialize secrets: {}", e)))?;

    fs::write(&secrets_path, secrets_content)
        .map_err(|e| crate::error::OcfgError::Io(e))?;

    // Set restrictive permissions
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&secrets_path)?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(&secrets_path, perms)?;
    }

    println!("Secrets generated and saved to: {:?}", secrets_path);
    println!("WARNING: Keep this file secure and never commit it to version control!");

    Ok(())
}
