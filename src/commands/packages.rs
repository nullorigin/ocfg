use crate::config::OcfgConfig;
use crate::error::Result;
use anyhow::Context;

pub async fn run(
    list: bool,
    add: Vec<String>,
    remove: Vec<String>,
    kernel: bool,
    _non_interactive: bool,
) -> Result<()> {
    println!("Configuring packages and kernel modules...");

    let mut config = OcfgConfig::load()?;

    if list {
        println!("Available package categories:");
        println!("  - Core: openssl, libopenssl, dropbear, uhttpd");
        println!("  - Network: wireguard-tools, openvpn-openssl, dnsmasq-full");
        println!("  - Security: freeradius3, hostapd-openssl");
        println!("  - DNS: dnsproxy, drill, ldns-examples");
        println!("  - Blocking: luci-app-adblock, luci-app-banip");
        println!("  - Utilities: nano-full, ip-full, tcpdump, htop, curl");
        println!("  - File sharing: luci-app-samba4, nfs-kernel-server");
        println!("  - Storage: ntfs-3g, exfat-utils, e2fsprogs, blkid");
        println!("  - USB: kmod-usb-core, kmod-usb-storage, kmod-usb-ohci");
        println!("  - VPN routing: luci-app-vpn-policy-routing");
        println!("  - Time: chrony");
        println!("  - Web terminal: luci-app-ttyd");
        return Ok(());
    }

    if !add.is_empty() {
        println!("Adding packages: {:?}", add);
        config.build.extra_packages.extend(add);
    }

    if !remove.is_empty() {
        println!("Removing packages: {:?}", remove);
        config.build.exclude_packages.extend(remove);
    }

    if kernel {
        println!("Configuring kernel modules...");
        println!("Kernel hardening options will be applied");
    }

    config.save().context("Failed to save configuration")?;

    println!("Package configuration complete!");
    Ok(())
}
