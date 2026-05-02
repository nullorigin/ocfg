use crate::config::OcfgConfig;
use crate::crypto;
use crate::error::Result;
use crate::err;

pub async fn run(syntax: bool, required: bool, secrets: bool, all: bool) -> Result<()> {
    println!("Validating configuration...");

    let config = OcfgConfig::load()?;

    let mut errors = Vec::new();
    let mut warnings = Vec::new();

    if all || syntax {
        println!("Checking configuration syntax...");
        // Syntax is validated during load, so if we're here, it's valid
        println!("  ✓ Configuration syntax is valid");
    }

    if all || required {
        println!("Checking required configuration values...");
        
        if config.network.wan_interface.is_empty() {
            errors.push("WAN interface name is required".to_string());
        }
        
        if config.network.lan_interface.is_empty() {
            errors.push("LAN interface name is required".to_string());
        }
        
        if config.dns.doh_upstream.is_empty() {
            errors.push("DNS over HTTPS upstream is required".to_string());
        }
        
        if config.certificates.common_name.is_empty() {
            errors.push("Certificate common name is required".to_string());
        }
        
        if errors.is_empty() {
            println!("  ✓ All required values are present");
        }
    }

    if all || secrets {
        println!("Checking secret security...");
        
        if let Some(ref secret) = config.secrets.radius_shared_secret {
            if secret.len() < 16 {
                warnings.push("RADIUS shared secret should be at least 16 characters".to_string());
            }
        } else {
            warnings.push("RADIUS shared secret not configured (will be auto-generated)".to_string());
        }
        
        if let Some(ref password) = config.secrets.radius_admin_password {
            if password.len() < 16 {
                warnings.push("RADIUS admin password should be at least 16 characters".to_string());
            }
        } else {
            warnings.push("RADIUS admin password not configured (will be auto-generated)".to_string());
        }
        
        if let Some(ref key) = config.secrets.encryption_key {
            if !crypto::is_valid_hex(key) || key.len() != 64 {
                errors.push("Encryption key must be 64 hex characters (32 bytes)".to_string());
            }
        }
        
        if let Some(ref key) = config.secrets.hmac_key {
            if !crypto::is_valid_hex(key) || key.len() != 64 {
                errors.push("HMAC key must be 64 hex characters (32 bytes)".to_string());
            }
        }
        
        if warnings.is_empty() && errors.is_empty() {
            println!("  ✓ Secrets are properly configured");
        }
    }

    // Print results
    if !errors.is_empty() {
        println!("\nErrors:");
        for error in &errors {
            println!("  ✗ {}", error);
        }
    }

    if !warnings.is_empty() {
        println!("\nWarnings:");
        for warning in &warnings {
            println!("  ⚠ {}", warning);
        }
    }

    if errors.is_empty() && warnings.is_empty() {
        println!("\n✓ Configuration is valid!");
        Ok(())
    } else if !errors.is_empty() {
        Err(err!(Validation, "Validation failed with {} error(s)", errors.len()))
    } else {
        println!("\n✓ Configuration is valid (with warnings)");
        Ok(())
    }
}
