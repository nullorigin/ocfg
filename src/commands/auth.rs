use crate::config::OcfgConfig;
use crate::crypto;
use crate::error::Result;
use crate::err;
use dialoguer::{Input, Confirm, Password};

pub async fn run(
    radius: bool,
    ssh: bool,
    web: bool,
    all: bool,
    non_interactive: bool,
) -> Result<()> {
    println!("Configuring authentication settings...");

    let mut config = OcfgConfig::load()?;

    if all || radius {
        println!("Configuring RADIUS authentication...");
        
        if non_interactive {
            if config.secrets.radius_shared_secret.is_none() {
                config.secrets.radius_shared_secret = Some(crypto::generate_radius_secret());
            }
            if config.secrets.radius_admin_password.is_none() {
                config.secrets.radius_admin_password = Some(crypto::generate_password(32));
            }
        } else {
            let secret: String = Input::new()
                .with_prompt("RADIUS shared secret (leave empty to auto-generate)")
                .allow_empty(true)
                .interact()?;
            
            config.secrets.radius_shared_secret = if secret.is_empty() {
                Some(crypto::generate_radius_secret())
            } else {
                Some(secret)
            };
        }
    }

    if all || ssh {
        println!("Configuring SSH authentication...");
        
        if non_interactive {
            // Use existing or generate
            if config.secrets.ssh_public_key.is_none() {
                println!("No SSH public key configured. You can add one manually.");
            }
        } else {
            let use_key = Confirm::new()
                .with_prompt("Configure SSH public key")
                .default(false)
                .interact()?;
            
            if use_key {
                let public_key = Input::new()
                    .with_prompt("SSH public key")
                    .interact()?;
                config.secrets.ssh_public_key = Some(public_key);
            }
        }
    }

    if all || web {
        println!("Configuring web interface authentication...");
        
        if non_interactive {
            if config.secrets.root_password_hash.is_none() {
                println!("No root password hash configured. Using default OpenWrt behavior.");
            }
        } else {
            let set_password = Confirm::new()
                .with_prompt("Set root password")
                .default(false)
                .interact()?;
            
            if set_password {
                let password = Password::new()
                    .with_prompt("Root password")
                    .interact()?;
                config.secrets.root_password_hash = Some(crypto::hash_password(&password));
            }
        }
    }

    config.save()
        .map_err(|e| err!(Config, "Failed to save configuration: {}", e))?;

    println!("Authentication configuration complete!");
    Ok(())
}
