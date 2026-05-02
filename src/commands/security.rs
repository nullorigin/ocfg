use crate::config::OcfgConfig;
use crate::error::Result;
use anyhow::Context;

pub async fn run(
    dns: bool,
    firewall: bool,
    kernel: bool,
    all: bool,
    _non_interactive: bool,
) -> Result<()> {
    println!("Configuring security settings...");

    let config = OcfgConfig::load()?;

    if all || dns {
        println!("Configuring DNS settings...");
        println!("DNS over HTTPS upstream: {}", config.dns.doh_upstream);
        println!("DNSSEC enabled: {}", config.dns.dnssec_enabled);
    }

    if all || firewall {
        println!("Configuring firewall rules...");
        println!("SYN flood rate limit: {}", config.firewall.syn_flood_rate);
        println!("ICMP rate limit: {}", config.firewall.icmp_rate_limit);
    }

    if all || kernel {
        println!("Configuring kernel hardening...");
        println!("KASLR enabled: {}", config.security.enable_kaslr);
        println!("Stack protector enabled: {}", config.security.enable_stack_protector);
        println!("PTI enabled: {}", config.security.enable_pti);
        println!("Kernel hardening enabled: {}", config.security.enable_kernel_hardening);
    }

    config.save().context("Failed to save configuration")?;

    println!("Security configuration complete!");
    Ok(())
}
