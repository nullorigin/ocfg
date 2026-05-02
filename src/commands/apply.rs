use crate::config::OcfgConfig;
use crate::templates::TemplateEngine;
use crate::error::Result;
use anyhow::Context;
use std::fs;
use std::path::PathBuf;

pub async fn run(openwrt_dir: String, dry_run: bool) -> Result<()> {
    println!("Applying configuration to OpenWrt build...");

    let openwrt_path = PathBuf::from(&openwrt_dir);
    
    if !openwrt_path.exists() {
        return Err(anyhow::anyhow!("OpenWrt directory does not exist: {}", openwrt_dir).into());
    }

    let config = OcfgConfig::load()?;
    let templates = TemplateEngine::new()?;

    // Generate and write configuration files
    let files_to_create = vec![
        ("setup-config.env", templates.render_setup_config_env(&config)?),
        ("setup-secrets.env", templates.render_setup_secrets_env(&config)?),
        ("files/etc/nftables.d/10-hardening.nft", templates.render_nftables_hardening(&config)?),
        ("files/etc/sysctl.d/20-hardening.conf", templates.render_sysctl_hardening(&config)?),
        ("package/network/services/dnsmasq/files/dhcp.conf", templates.render_dnsmasq_config(&config)?),
        ("package/network/config/firewall/files/firewall.config", templates.render_firewall_config(&config)?),
    ];

    for (relative_path, content) in files_to_create {
        let full_path = openwrt_path.join(relative_path);
        
        if dry_run {
            println!("Would create: {}", full_path.display());
            println!("--- Content preview ---");
            println!("{}", content.lines().take(10).collect::<Vec<_>>().join("\n"));
            if content.lines().count() > 10 {
                println!("... ({} more lines)", content.lines().count() - 10);
            }
            println!("--- End preview ---\n");
        } else {
            if let Some(parent) = full_path.parent() {
                fs::create_dir_all(parent)
                    .context("Failed to create directory")?;
            }
            
            fs::write(&full_path, content)
                .context("Failed to write file")?;
            
            println!("Created: {}", full_path.display());
        }
    }

    if dry_run {
        println!("\nDry run complete. No files were modified.");
    } else {
        println!("\nConfiguration applied successfully!");
        println!("You can now run ./setup-build.sh in the OpenWrt directory.");
    }

    Ok(())
}
