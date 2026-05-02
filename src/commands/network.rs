use crate::config::OcfgConfig;
use crate::error::Result;
use anyhow::Context;

pub async fn run(
    wan: bool,
    lan: bool,
    wifi: bool,
    vpn: bool,
    all: bool,
    _non_interactive: bool,
) -> Result<()> {
    println!("Configuring network settings...");

    let config = OcfgConfig::load()?;

    if all || wan {
        println!("Configuring WAN interface...");
        println!("WAN interface: {}", config.network.wan_interface);
    }

    if all || lan {
        println!("Configuring LAN interface...");
        println!("LAN interface: {}", config.network.lan_interface);
    }

    if all || wifi {
        println!("Configuring Wi-Fi settings...");
        println!("2.4GHz SSID: {}", config.wifi.ssid_24g);
        println!("5GHz SSID: {}", config.wifi.ssid_5g);
        println!("Country: {}", config.wifi.country);
    }

    if all || vpn {
        println!("Configuring VPN settings...");
        println!("WireGuard port: {}", config.vpn.wireguard_port);
        println!("OpenVPN port: {}", config.vpn.openvpn_port);
    }

    config.save().context("Failed to save configuration")?;

    println!("Network configuration complete!");
    Ok(())
}
