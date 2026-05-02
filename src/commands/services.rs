use crate::config::OcfgConfig;
use crate::error::Result;
use anyhow::Context;

pub async fn run(
    dns_proxy: bool,
    adblock: bool,
    banip: bool,
    ntp: bool,
    all: bool,
    _non_interactive: bool,
) -> Result<()> {
    println!("Configuring services...");

    let mut config = OcfgConfig::load()?;

    if all || dns_proxy {
        println!("Configuring DNS proxy...");
        println!("DNS proxy will forward to: {}", config.dns.doh_upstream);
        println!("Listen address: {}:{}", config.dns.proxy_listen_addr, config.dns.proxy_listen_port);
    }

    if all || adblock {
        println!("Configuring ad blocking...");
        config.features.adblock_enabled = true;
        println!("Ad blocking enabled: {}", config.features.adblock_enabled);
    }

    if all || banip {
        println!("Configuring IP blocking...");
        config.features.banip_enabled = true;
        println!("IP blocking enabled: {}", config.features.banip_enabled);
    }

    if all || ntp {
        println!("Configuring NTP service...");
        println!("Timezone: {}", config.time.timezone);
        println!("NTP servers: {:?}", config.time.ntp_servers);
    }

    config.save().context("Failed to save configuration")?;

    println!("Service configuration complete!");
    Ok(())
}
