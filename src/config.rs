use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OcfgConfig {
    pub network: NetworkConfig,
    pub dns: DnsConfig,
    pub wifi: WifiConfig,
    pub radius: RadiusConfig,
    pub firewall: FirewallConfig,
    pub ssh: SshConfig,
    pub web: WebConfig,
    pub vpn: VpnConfig,
    pub storage: StorageConfig,
    pub time: TimeConfig,
    pub build: BuildConfig,
    pub features: FeatureFlags,
    pub security: SecurityConfig,
    pub secrets: SecretsConfig,
    pub certificates: CertificateConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub wan_interface: String,
    pub lan_interface: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsConfig {
    pub doh_upstream: String,
    pub dot_bootstrap: String,
    pub proxy_listen_addr: String,
    pub proxy_listen_port: u16,
    pub dnssec_enabled: bool,
    pub dnssec_root_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WifiConfig {
    pub ssid_24g: String,
    pub ssid_5g: String,
    pub country: String,
    pub isolate_guest: bool,
    pub hidden_ssid: bool,
    pub max_assoc: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RadiusConfig {
    pub auth_port: u16,
    pub acct_port: u16,
    pub shared_secret: Option<String>,
    pub admin_password: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallConfig {
    pub syn_flood_rate: u32,
    pub conn_flood_rate: u32,
    pub icmp_rate_limit: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshConfig {
    pub idle_timeout: u32,
    pub public_key: Option<String>,
    pub authorized_keys_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebConfig {
    pub http_port: u16,
    pub https_port: u16,
    pub max_connections: u32,
    pub admin_user: String,
    pub admin_password_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VpnConfig {
    pub wireguard_port: u16,
    pub openvpn_port: u16,
    pub wireguard_private_key: Option<String>,
    pub wireguard_preshared_key: Option<String>,
    pub openvpn_static_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    pub usb_mount_point: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeConfig {
    pub timezone: String,
    pub ntp_servers: Vec<String>,
    pub ntp_listen_addr: String,
    pub ntp_allow_network: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildConfig {
    pub jobs: u32,
    pub verbose: bool,
    pub extra_packages: Vec<String>,
    pub exclude_packages: Vec<String>,
    pub crypto_library: CryptoLibrary,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CryptoLibrary {
    #[serde(rename = "openssl")]
    OpenSSL,
    #[serde(rename = "mbedtls")]
    MbedTLS,
    #[serde(rename = "wolfssl")]
    WolfSSL,
}

impl Default for CryptoLibrary {
    fn default() -> Self {
        CryptoLibrary::OpenSSL
    }
}

impl std::fmt::Display for CryptoLibrary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoLibrary::OpenSSL => write!(f, "openssl"),
            CryptoLibrary::MbedTLS => write!(f, "mbedtls"),
            CryptoLibrary::WolfSSL => write!(f, "wolfssl"),
        }
    }
}

impl std::str::FromStr for CryptoLibrary {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "openssl" => Ok(CryptoLibrary::OpenSSL),
            "mbedtls" => Ok(CryptoLibrary::MbedTLS),
            "wolfssl" => Ok(CryptoLibrary::WolfSSL),
            _ => Err(format!("Invalid crypto library: {}. Valid options: openssl, mbedtls, wolfssl", s)),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureFlags {
    pub adblock_enabled: bool,
    pub banip_enabled: bool,
    pub ipv6_enabled: bool,
    pub vpn_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub enable_kaslr: bool,
    pub enable_stack_protector: bool,
    pub enable_pti: bool,
    pub enable_kernel_hardening: bool,
    pub disable_module_loading: bool,
    pub enable_pointer_restrictions: bool,
    pub enable_refcount_hardening: bool,
    pub enable_slab_hardening: bool,
    pub block_cloudflare_dns: bool,
    pub block_telemetry_domains: Vec<String>,
    pub enable_dns_logging: bool,
    pub enable_syn_cookies: bool,
    pub enable_rp_filter: bool,
    pub enable_src_validation: bool,
    pub enable_icmp_ratelimit: bool,
    pub enable_tcp_timestamp_protection: bool,
    pub disable_core_dumps: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretsConfig {
    pub radius_shared_secret: Option<String>,
    pub radius_admin_password: Option<String>,
    pub ca_key_password: Option<String>,
    pub server_key_password: Option<String>,
    pub root_password_hash: Option<String>,
    pub ssh_public_key: Option<String>,
    pub wifi_radius_secret: Option<String>,
    pub wired_radius_secret: Option<String>,
    pub wifi_24g_password: Option<String>,
    pub wifi_5g_password: Option<String>,
    pub encryption_key: Option<String>,
    pub hmac_key: Option<String>,
    pub ddns_api_key: Option<String>,
    pub cloudflare_api_token: Option<String>,
    pub cloudflare_zone_id: Option<String>,
}

impl Default for SecretsConfig {
    fn default() -> Self {
        Self {
            radius_shared_secret: None,
            radius_admin_password: None,
            ca_key_password: None,
            server_key_password: None,
            root_password_hash: None,
            ssh_public_key: None,
            wifi_radius_secret: None,
            wired_radius_secret: None,
            wifi_24g_password: None,
            wifi_5g_password: None,
            encryption_key: None,
            hmac_key: None,
            ddns_api_key: None,
            cloudflare_api_token: None,
            cloudflare_zone_id: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateConfig {
    pub country: String,
    pub state: String,
    pub locality: String,
    pub organization: String,
    pub organizational_unit: String,
    pub common_name: String,
    pub email: String,
}

impl Default for OcfgConfig {
    fn default() -> Self {
        Self {
            network: NetworkConfig {
                wan_interface: "wan".to_string(),
                lan_interface: "br-lan".to_string(),
            },
            dns: DnsConfig {
                doh_upstream: "https://dns.quad9.net/dns-query".to_string(),
                dot_bootstrap: "9.9.9.9:853".to_string(),
                proxy_listen_addr: "127.0.0.1".to_string(),
                proxy_listen_port: 5353,
                dnssec_enabled: true,
                dnssec_root_key: None,
            },
            wifi: WifiConfig {
                ssid_24g: "Enterprise-2.4G".to_string(),
                ssid_5g: "Enterprise-5G".to_string(),
                country: "US".to_string(),
                isolate_guest: false,
                hidden_ssid: false,
                max_assoc: 32,
            },
            radius: RadiusConfig {
                auth_port: 1812,
                acct_port: 1813,
                shared_secret: None,
                admin_password: None,
            },
            firewall: FirewallConfig {
                syn_flood_rate: 20,
                conn_flood_rate: 50,
                icmp_rate_limit: 5,
            },
            ssh: SshConfig {
                idle_timeout: 5,
                public_key: None,
                authorized_keys_path: "/etc/dropbear/authorized_keys".to_string(),
            },
            web: WebConfig {
                http_port: 80,
                https_port: 443,
                max_connections: 20,
                admin_user: "root".to_string(),
                admin_password_hash: None,
            },
            vpn: VpnConfig {
                wireguard_port: 51820,
                openvpn_port: 1194,
                wireguard_private_key: None,
                wireguard_preshared_key: None,
                openvpn_static_key: None,
            },
            storage: StorageConfig {
                usb_mount_point: "/mnt/usb".to_string(),
            },
            time: TimeConfig {
                timezone: "UTC".to_string(),
                ntp_servers: vec![
                    "0.pool.ntp.org".to_string(),
                    "1.pool.ntp.org".to_string(),
                    "2.pool.ntp.org".to_string(),
                    "3.pool.ntp.org".to_string(),
                ],
                ntp_listen_addr: "0.0.0.0".to_string(),
                ntp_allow_network: "192.168.0.0/16".to_string(),
            },
            build: BuildConfig {
                jobs: 0,
                verbose: true,
                extra_packages: vec![],
                exclude_packages: vec![],
                crypto_library: CryptoLibrary::OpenSSL,
            },
            features: FeatureFlags {
                adblock_enabled: true,
                banip_enabled: true,
                ipv6_enabled: false,
                vpn_enabled: true,
            },
            security: SecurityConfig {
                enable_kaslr: true,
                enable_stack_protector: true,
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
            },
            secrets: SecretsConfig {
                radius_shared_secret: None,
                radius_admin_password: None,
                ca_key_password: None,
                server_key_password: None,
                root_password_hash: None,
                ssh_public_key: None,
                wifi_radius_secret: None,
                wired_radius_secret: None,
                wifi_24g_password: None,
                wifi_5g_password: None,
                encryption_key: None,
                hmac_key: None,
                ddns_api_key: None,
                cloudflare_api_token: None,
                cloudflare_zone_id: None,
            },
            certificates: CertificateConfig {
                country: "US".to_string(),
                state: "California".to_string(),
                locality: "San Francisco".to_string(),
                organization: "My Organization".to_string(),
                organizational_unit: "IT Department".to_string(),
                common_name: "router.local".to_string(),
                email: "admin@router.local".to_string(),
            },
        }
    }
}

impl OcfgConfig {
    pub fn load() -> Result<Self> {
        let config_path = Self::config_path();
        
        if config_path.exists() {
            let content = fs::read_to_string(&config_path)?;
            let config: OcfgConfig = toml::from_str(&content)
                .map_err(|e| anyhow::anyhow!("Failed to parse config file: {}", e))?;
            Ok(config)
        } else {
            Ok(Self::default())
        }
    }

    pub fn save(&self) -> Result<()> {
        let config_path = Self::config_path();
        
        if let Some(parent) = config_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let content = toml::to_string_pretty(self)
            .map_err(|e| anyhow::anyhow!("Failed to serialize config: {}", e))?;
        
        fs::write(&config_path, content)?;
        Ok(())
    }

    pub fn config_path() -> PathBuf {
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("ocfg")
            .join("config.toml")
    }

    pub fn secrets_path() -> PathBuf {
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("ocfg")
            .join("secrets.toml")
    }
}
