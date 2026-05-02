use crate::config::OcfgConfig;
use crate::error::Result;
use crate::crypto;
use dialoguer::{Confirm, Input};
use indicatif::{ProgressBar, ProgressStyle};

/// Run interactive configuration wizard
pub fn interactive_wizard() -> Result<OcfgConfig> {
    println!("OpenWrt Configuration Wizard");
    println!("============================\n");

    let mut config = OcfgConfig::default();

    // Network configuration
    config.network = prompt_network()?;

    // DNS configuration
    config.dns = prompt_dns()?;

    // WiFi configuration
    config.wifi = prompt_wifi()?;

    // RADIUS configuration
    config.radius = prompt_radius()?;

    // Firewall configuration
    config.firewall = prompt_firewall()?;

    // SSH configuration
    config.ssh = prompt_ssh()?;

    // Web interface configuration
    config.web = prompt_web()?;

    // VPN configuration
    config.vpn = prompt_vpn()?;

    // Storage configuration
    config.storage = prompt_storage()?;

    // Time configuration
    config.time = prompt_time()?;

    // Build configuration
    config.build = prompt_build()?;

    // Feature flags
    config.features = prompt_features()?;

    // Security configuration
    config.security = prompt_security()?;

    // Certificate configuration
    config.certificates = prompt_certificates()?;

    // Secrets configuration
    config.secrets = prompt_secrets()?;

    println!("\nConfiguration complete!");
    Ok(config)
}

fn prompt_network() -> Result<crate::config::NetworkConfig> {
    println!("\n--- Network Configuration ---");

    let wan_interface = Input::new()
        .with_prompt("WAN interface name")
        .default("wan".to_string())
        .interact()?;

    let lan_interface = Input::new()
        .with_prompt("LAN bridge interface name")
        .default("br-lan".to_string())
        .interact()?;

    Ok(crate::config::NetworkConfig {
        wan_interface,
        lan_interface,
    })
}

fn prompt_dns() -> Result<crate::config::DnsConfig> {
    println!("\n--- DNS Configuration ---");

    let doh_upstream = Input::new()
        .with_prompt("DNS over HTTPS upstream")
        .default("https://dns.quad9.net/dns-query".to_string())
        .interact()?;

    let dot_bootstrap = Input::new()
        .with_prompt("DNS over TLS bootstrap")
        .default("9.9.9.9:853".to_string())
        .interact()?;

    let dnssec_enabled = Confirm::new()
        .with_prompt("Enable DNSSEC validation")
        .default(true)
        .interact()?;

    Ok(crate::config::DnsConfig {
        doh_upstream,
        dot_bootstrap,
        proxy_listen_addr: "127.0.0.1".to_string(),
        proxy_listen_port: 5353,
        dnssec_enabled,
        dnssec_root_key: None,
    })
}

fn prompt_wifi() -> Result<crate::config::WifiConfig> {
    println!("\n--- Wi-Fi Configuration ---");

    let ssid_24g = Input::new()
        .with_prompt("2.4GHz SSID")
        .default("Enterprise-2.4G".to_string())
        .interact()?;

    let ssid_5g = Input::new()
        .with_prompt("5GHz SSID")
        .default("Enterprise-5G".to_string())
        .interact()?;

    let country = Input::new()
        .with_prompt("Country code")
        .default("US".to_string())
        .interact()?;

    let isolate_guest = Confirm::new()
        .with_prompt("Isolate guest clients")
        .default(false)
        .interact()?;

    Ok(crate::config::WifiConfig {
        ssid_24g,
        ssid_5g,
        country,
        isolate_guest,
        hidden_ssid: false,
        max_assoc: 32,
    })
}

fn prompt_radius() -> Result<crate::config::RadiusConfig> {
    println!("\n--- RADIUS Configuration ---");

    let auth_port: u16 = Input::new()
        .with_prompt("RADIUS authentication port")
        .default("1812".to_string())
        .interact()?
        .parse()
        .map_err(|_| crate::error::OcfgError::invalid_value("Invalid port number".to_string()))?;

    let acct_port: u16 = Input::new()
        .with_prompt("RADIUS accounting port")
        .default("1813".to_string())
        .interact()?
        .parse()
        .map_err(|_| crate::error::OcfgError::invalid_value("Invalid port number".to_string()))?;

    Ok(crate::config::RadiusConfig {
        auth_port,
        acct_port,
        shared_secret: None,
        admin_password: None,
    })
}

fn prompt_firewall() -> Result<crate::config::FirewallConfig> {
    println!("\n--- Firewall Configuration ---");

    let syn_flood_rate: u32 = Input::new()
        .with_prompt("SYN flood rate limit (packets/sec)")
        .default("20".to_string())
        .interact()?
        .parse()
        .map_err(|_| crate::error::OcfgError::invalid_value("Invalid rate limit".to_string()))?;

    Ok(crate::config::FirewallConfig {
        syn_flood_rate,
        conn_flood_rate: 50,
        icmp_rate_limit: 5,
    })
}

fn prompt_ssh() -> Result<crate::config::SshConfig> {
    println!("\n--- SSH Configuration ---");

    let idle_timeout: u32 = Input::new()
        .with_prompt("SSH idle timeout (minutes)")
        .default("5".to_string())
        .interact()?
        .parse()
        .map_err(|_| crate::error::OcfgError::invalid_value("Invalid timeout".to_string()))?;

    let use_key = Confirm::new()
        .with_prompt("Configure SSH public key")
        .default(false)
        .interact()?;

    let public_key = if use_key {
        Some(Input::new()
            .with_prompt("SSH public key")
            .interact()?)
    } else {
        None
    };

    Ok(crate::config::SshConfig {
        idle_timeout,
        public_key,
        authorized_keys_path: "/etc/dropbear/authorized_keys".to_string(),
    })
}

fn prompt_web() -> Result<crate::config::WebConfig> {
    println!("\n--- Web Interface Configuration ---");

    let http_port: u16 = Input::new()
        .with_prompt("HTTP port")
        .default("80".to_string())
        .interact()?
        .parse()
        .map_err(|_| crate::error::OcfgError::invalid_value("Invalid port number".to_string()))?;

    let https_port: u16 = Input::new()
        .with_prompt("HTTPS port")
        .default("443".to_string())
        .interact()?
        .parse()
        .map_err(|_| crate::error::OcfgError::invalid_value("Invalid port number".to_string()))?;

    Ok(crate::config::WebConfig {
        http_port,
        https_port,
        max_connections: 20,
        admin_user: "root".to_string(),
        admin_password_hash: None,
    })
}

fn prompt_vpn() -> Result<crate::config::VpnConfig> {
    println!("\n--- VPN Configuration ---");

    let wireguard_port: u16 = Input::new()
        .with_prompt("WireGuard port")
        .default("51820".to_string())
        .interact()?
        .parse()
        .map_err(|_| crate::error::OcfgError::invalid_value("Invalid port number".to_string()))?;

    let openvpn_port: u16 = Input::new()
        .with_prompt("OpenVPN port")
        .default("1194".to_string())
        .interact()?
        .parse()
        .map_err(|_| crate::error::OcfgError::invalid_value("Invalid port number".to_string()))?;

    Ok(crate::config::VpnConfig {
        wireguard_port,
        openvpn_port,
        wireguard_private_key: None,
        wireguard_preshared_key: None,
        openvpn_static_key: None,
    })
}

fn prompt_storage() -> Result<crate::config::StorageConfig> {
    println!("\n--- Storage Configuration ---");

    let usb_mount_point = Input::new()
        .with_prompt("USB mount point")
        .default("/mnt/usb".to_string())
        .interact()?;

    Ok(crate::config::StorageConfig {
        usb_mount_point,
    })
}

fn prompt_time() -> Result<crate::config::TimeConfig> {
    println!("\n--- Time Configuration ---");

    let timezone = Input::new()
        .with_prompt("Timezone")
        .default("UTC".to_string())
        .interact()?;

    Ok(crate::config::TimeConfig {
        timezone,
        ntp_servers: vec![
            "0.pool.ntp.org".to_string(),
            "1.pool.ntp.org".to_string(),
            "2.pool.ntp.org".to_string(),
            "3.pool.ntp.org".to_string(),
        ],
        ntp_listen_addr: "0.0.0.0".to_string(),
        ntp_allow_network: "192.168.0.0/16".to_string(),
    })
}

fn prompt_build() -> Result<crate::config::BuildConfig> {
    println!("\n--- Build Configuration ---");

    let jobs: u32 = Input::new()
        .with_prompt("Parallel build jobs (0 = auto)")
        .default("0".to_string())
        .interact()?
        .parse()
        .map_err(|_| crate::error::OcfgError::invalid_value("Invalid job count".to_string()))?;

    let verbose = Confirm::new()
        .with_prompt("Verbose build output")
        .default(true)
        .interact()?;

    println!("\n--- Crypto Library Selection ---");
    println!("Choose the TLS/crypto library for the build:");
    println!("  1. OpenSSL - Most widely used, best compatibility");
    println!("  2. MbedTLS - Smaller footprint, suitable for embedded devices");
    println!("  3. WolfSSL - Small footprint, FIPS certified options");

    let crypto_selection = Input::new()
        .with_prompt("Select crypto library (1-3)")
        .default("1".to_string())
        .interact()?;

    let crypto_library = match crypto_selection.as_str() {
        "1" => crate::config::CryptoLibrary::OpenSSL,
        "2" => crate::config::CryptoLibrary::MbedTLS,
        "3" => crate::config::CryptoLibrary::WolfSSL,
        _ => crate::config::CryptoLibrary::OpenSSL,
    };

    println!("Selected: {}", crypto_library);

    Ok(crate::config::BuildConfig {
        jobs,
        verbose,
        extra_packages: vec![],
        exclude_packages: vec![],
        crypto_library,
    })
}

fn prompt_features() -> Result<crate::config::FeatureFlags> {
    println!("\n--- Feature Flags ---");

    let adblock_enabled = Confirm::new()
        .with_prompt("Enable ad blocking")
        .default(true)
        .interact()?;

    let banip_enabled = Confirm::new()
        .with_prompt("Enable IP blocking")
        .default(true)
        .interact()?;

    let ipv6_enabled = Confirm::new()
        .with_prompt("Enable IPv6")
        .default(false)
        .interact()?;

    Ok(crate::config::FeatureFlags {
        adblock_enabled,
        banip_enabled,
        ipv6_enabled,
        vpn_enabled: true,
    })
}

fn prompt_security() -> Result<crate::config::SecurityConfig> {
    println!("\n--- Security Configuration ---");

    let enable_kaslr = Confirm::new()
        .with_prompt("Enable KASLR")
        .default(true)
        .interact()?;

    let enable_stack_protector = Confirm::new()
        .with_prompt("Enable kernel stack protector")
        .default(true)
        .interact()?;

    Ok(crate::config::SecurityConfig {
        enable_kaslr,
        enable_stack_protector,
        enable_pti: true,
        enable_kernel_hardening: true,
        disable_module_loading: false,
        enable_pointer_restrictions: true,
        enable_refcount_hardening: true,
        enable_slab_hardening: true,
        block_cloudflare_dns: false,
        block_telemetry_domains: vec![],
        enable_dns_logging: false,
        enable_syn_cookies: true,
        enable_rp_filter: true,
        enable_src_validation: true,
        enable_icmp_ratelimit: true,
        enable_tcp_timestamp_protection: true,
        disable_core_dumps: true,
    })
}

fn prompt_certificates() -> Result<crate::config::CertificateConfig> {
    println!("\n--- Certificate Configuration ---");

    let country = Input::new()
        .with_prompt("Country code")
        .default("US".to_string())
        .interact()?;

    let state = Input::new()
        .with_prompt("State/Province")
        .default("California".to_string())
        .interact()?;

    let organization = Input::new()
        .with_prompt("Organization")
        .default("My Organization".to_string())
        .interact()?;

    let common_name = Input::new()
        .with_prompt("Common name (hostname)")
        .default("router.local".to_string())
        .interact()?;

    Ok(crate::config::CertificateConfig {
        country,
        state,
        locality: "San Francisco".to_string(),
        organization,
        organizational_unit: "IT Department".to_string(),
        common_name: common_name.clone(),
        email: format!("admin@{}", common_name),
    })
}

fn prompt_secrets() -> Result<crate::config::SecretsConfig> {
    println!("\n--- Secrets Configuration ---");
    println!("Secrets can be auto-generated or provided manually.");

    let auto_generate = Confirm::new()
        .with_prompt("Auto-generate all secrets")
        .default(true)
        .interact()?;

    if auto_generate {
        Ok(crate::config::SecretsConfig {
            radius_shared_secret: Some(crypto::generate_radius_secret()?),
            radius_admin_password: Some(crypto::generate_password(32)?),
            ca_key_password: Some(crypto::generate_password(32)?),
            server_key_password: Some(crypto::generate_password(32)?),
            root_password_hash: None,
            ssh_public_key: None,
            wifi_radius_secret: Some(crypto::generate_radius_secret()?),
            wired_radius_secret: Some(crypto::generate_radius_secret()?),
            wifi_24g_password: Some(crypto::generate_password(24)?),
            wifi_5g_password: Some(crypto::generate_password(24)?),
            encryption_key: Some(crypto::generate_encryption_key()?),
            hmac_key: Some(crypto::generate_hmac_key()?),
            ddns_api_key: None,
            cloudflare_api_token: None,
            cloudflare_zone_id: None,
        })
    } else {
        Ok(crate::config::SecretsConfig::default())
    }
}

pub fn show_progress(message: String) -> ProgressBar {
    let pb = ProgressBar::new_spinner();
    pb.set_style(ProgressStyle::default_spinner()
        .template("{spinner} {msg}")
        .unwrap());
    pb.set_message(message);
    pb.enable_steady_tick(std::time::Duration::from_millis(100));
    pb
}
