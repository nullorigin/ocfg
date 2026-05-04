use crate::error::Result;
use crate::err;
use crate::json::{ToJson, FromJson, JsonObjectBuilder, FieldExtractor};
use crate::json::JsonValue;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::str::FromStr;

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

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
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
                .map_err(|e| err!(Config, "Failed to parse config file: {}", e))?;
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
            .map_err(|e| err!(Config, "Failed to serialize config: {}", e))?;
        
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
// ============================================================================
// JSON Serialization Implementations
// ============================================================================

impl ToJson for CryptoLibrary {
    fn to_json(&self) -> JsonValue {
        JsonValue::string(self.to_string())
    }
}

impl ToJson for NetworkConfig {
    fn to_json(&self) -> JsonValue {
        JsonObjectBuilder::new()
            .insert_string("wan_interface", &self.wan_interface)
            .insert_string("lan_interface", &self.lan_interface)
            .build()
    }
}

impl ToJson for DnsConfig {
    fn to_json(&self) -> JsonValue {
        JsonObjectBuilder::new()
            .insert_string("doh_upstream", &self.doh_upstream)
            .insert_string("dot_bootstrap", &self.dot_bootstrap)
            .insert_string("proxy_listen_addr", &self.proxy_listen_addr)
            .insert_u16("proxy_listen_port", self.proxy_listen_port)
            .insert_bool("dnssec_enabled", self.dnssec_enabled)
            .insert_option("dnssec_root_key", &self.dnssec_root_key)
            .build()
    }
}

impl ToJson for WifiConfig {
    fn to_json(&self) -> JsonValue {
        JsonObjectBuilder::new()
            .insert_string("ssid_24g", &self.ssid_24g)
            .insert_string("ssid_5g", &self.ssid_5g)
            .insert_string("country", &self.country)
            .insert_bool("isolate_guest", self.isolate_guest)
            .insert_bool("hidden_ssid", self.hidden_ssid)
            .insert_u32("max_assoc", self.max_assoc)
            .build()
    }
}

impl ToJson for BuildConfig {
    fn to_json(&self) -> JsonValue {
        JsonObjectBuilder::new()
            .insert_u32("jobs", self.jobs)
            .insert_bool("verbose", self.verbose)
            .insert_vec("extra_packages", &self.extra_packages)
            .insert_vec("exclude_packages", &self.exclude_packages)
            .insert("crypto_library", self.crypto_library.to_json())
            .build()
    }
}

impl ToJson for FeatureFlags {
    fn to_json(&self) -> JsonValue {
        JsonObjectBuilder::new()
            .insert_bool("adblock_enabled", self.adblock_enabled)
            .insert_bool("banip_enabled", self.banip_enabled)
            .insert_bool("ipv6_enabled", self.ipv6_enabled)
            .insert_bool("vpn_enabled", self.vpn_enabled)
            .build()
    }
}

impl ToJson for RadiusConfig {
    fn to_json(&self) -> JsonValue {
        JsonObjectBuilder::new()
            .insert_u16("auth_port", self.auth_port)
            .insert_u16("acct_port", self.acct_port)
            .insert_option("shared_secret", &self.shared_secret)
            .insert_option("admin_password", &self.admin_password)
            .build()
    }
}

impl ToJson for FirewallConfig {
    fn to_json(&self) -> JsonValue {
        JsonObjectBuilder::new()
            .insert_u32("syn_flood_rate", self.syn_flood_rate)
            .insert_u32("conn_flood_rate", self.conn_flood_rate)
            .insert_u32("icmp_rate_limit", self.icmp_rate_limit)
            .build()
    }
}

impl ToJson for SshConfig {
    fn to_json(&self) -> JsonValue {
        JsonObjectBuilder::new()
            .insert_u32("idle_timeout", self.idle_timeout)
            .insert_option("public_key", &self.public_key)
            .insert_string("authorized_keys_path", &self.authorized_keys_path)
            .build()
    }
}

impl ToJson for WebConfig {
    fn to_json(&self) -> JsonValue {
        JsonObjectBuilder::new()
            .insert_u16("http_port", self.http_port)
            .insert_u16("https_port", self.https_port)
            .insert_u32("max_connections", self.max_connections)
            .insert_string("admin_user", &self.admin_user)
            .insert_option("admin_password_hash", &self.admin_password_hash)
            .build()
    }
}

impl ToJson for VpnConfig {
    fn to_json(&self) -> JsonValue {
        JsonObjectBuilder::new()
            .insert_u16("wireguard_port", self.wireguard_port)
            .insert_u16("openvpn_port", self.openvpn_port)
            .insert_option("wireguard_private_key", &self.wireguard_private_key)
            .insert_option("wireguard_preshared_key", &self.wireguard_preshared_key)
            .insert_option("openvpn_static_key", &self.openvpn_static_key)
            .build()
    }
}

impl ToJson for StorageConfig {
    fn to_json(&self) -> JsonValue {
        JsonObjectBuilder::new()
            .insert_string("usb_mount_point", &self.usb_mount_point)
            .build()
    }
}

impl ToJson for TimeConfig {
    fn to_json(&self) -> JsonValue {
        JsonObjectBuilder::new()
            .insert_string("timezone", &self.timezone)
            .insert_vec("ntp_servers", &self.ntp_servers)
            .insert_string("ntp_listen_addr", &self.ntp_listen_addr)
            .insert_string("ntp_allow_network", &self.ntp_allow_network)
            .build()
    }
}

impl ToJson for SecurityConfig {
    fn to_json(&self) -> JsonValue {
        JsonObjectBuilder::new()
            .insert_bool("enable_kaslr", self.enable_kaslr)
            .insert_bool("enable_stack_protector", self.enable_stack_protector)
            .insert_bool("enable_pti", self.enable_pti)
            .insert_bool("enable_kernel_hardening", self.enable_kernel_hardening)
            .insert_bool("disable_module_loading", self.disable_module_loading)
            .insert_bool("enable_pointer_restrictions", self.enable_pointer_restrictions)
            .insert_bool("enable_refcount_hardening", self.enable_refcount_hardening)
            .insert_bool("enable_slab_hardening", self.enable_slab_hardening)
            .insert_bool("block_cloudflare_dns", self.block_cloudflare_dns)
            .insert_vec("block_telemetry_domains", &self.block_telemetry_domains)
            .insert_bool("enable_dns_logging", self.enable_dns_logging)
            .insert_bool("enable_syn_cookies", self.enable_syn_cookies)
            .insert_bool("enable_rp_filter", self.enable_rp_filter)
            .insert_bool("enable_src_validation", self.enable_src_validation)
            .insert_bool("enable_icmp_ratelimit", self.enable_icmp_ratelimit)
            .insert_bool("enable_tcp_timestamp_protection", self.enable_tcp_timestamp_protection)
            .insert_bool("disable_core_dumps", self.disable_core_dumps)
            .build()
    }
}

impl ToJson for SecretsConfig {
    fn to_json(&self) -> JsonValue {
        JsonObjectBuilder::new()
            .insert_option("radius_shared_secret", &self.radius_shared_secret)
            .insert_option("radius_admin_password", &self.radius_admin_password)
            .insert_option("ca_key_password", &self.ca_key_password)
            .insert_option("server_key_password", &self.server_key_password)
            .insert_option("root_password_hash", &self.root_password_hash)
            .insert_option("ssh_public_key", &self.ssh_public_key)
            .insert_option("wifi_radius_secret", &self.wifi_radius_secret)
            .insert_option("wired_radius_secret", &self.wired_radius_secret)
            .insert_option("wifi_24g_password", &self.wifi_24g_password)
            .insert_option("wifi_5g_password", &self.wifi_5g_password)
            .insert_option("encryption_key", &self.encryption_key)
            .insert_option("hmac_key", &self.hmac_key)
            .insert_option("ddns_api_key", &self.ddns_api_key)
            .insert_option("cloudflare_api_token", &self.cloudflare_api_token)
            .insert_option("cloudflare_zone_id", &self.cloudflare_zone_id)
            .build()
    }
}

impl ToJson for CertificateConfig {
    fn to_json(&self) -> JsonValue {
        JsonObjectBuilder::new()
            .insert_string("country", &self.country)
            .insert_string("state", &self.state)
            .insert_string("locality", &self.locality)
            .insert_string("organization", &self.organization)
            .insert_string("organizational_unit", &self.organizational_unit)
            .insert_string("common_name", &self.common_name)
            .insert_string("email", &self.email)
            .build()
    }
}

impl ToJson for OcfgConfig {
    fn to_json(&self) -> JsonValue {
        JsonObjectBuilder::new()
            .insert("network", self.network.to_json())
            .insert("dns", self.dns.to_json())
            .insert("wifi", self.wifi.to_json())
            .insert("radius", self.radius.to_json())
            .insert("firewall", self.firewall.to_json())
            .insert("ssh", self.ssh.to_json())
            .insert("web", self.web.to_json())
            .insert("vpn", self.vpn.to_json())
            .insert("storage", self.storage.to_json())
            .insert("time", self.time.to_json())
            .insert("build", self.build.to_json())
            .insert("features", self.features.to_json())
            .insert("security", self.security.to_json())
            .insert("secrets", self.secrets.to_json())
            .insert("certificates", self.certificates.to_json())
            .build()
    }
}

// ============================================================================
// JSON Deserialization Implementations
// ============================================================================

impl FromJson for CryptoLibrary {
    fn from_json(value: JsonValue) -> Result<Self> {
        let s = value.as_str()
            .ok_or_else(|| err!(InvalidValue, "CryptoLibrary: expected string"))?;
        CryptoLibrary::from_str(s)
            .map_err(|e| err!(InvalidValue, "CryptoLibrary: {}", e))
    }
}

impl FromJson for NetworkConfig {
    fn from_json(value: JsonValue) -> Result<Self> {
        let obj = value.as_object()
            .ok_or_else(|| err!(InvalidValue, "NetworkConfig: expected object"))?;
        let extractor = FieldExtractor::new(obj, "NetworkConfig");
        Ok(NetworkConfig {
            wan_interface: extractor.string("wan_interface")?,
            lan_interface: extractor.string("lan_interface")?,
        })
    }
}

impl FromJson for DnsConfig {
    fn from_json(value: JsonValue) -> Result<Self> {
        let obj = value.as_object()
            .ok_or_else(|| err!(InvalidValue, "DnsConfig: expected object"))?;
        let extractor = FieldExtractor::new(obj, "DnsConfig");
        Ok(DnsConfig {
            doh_upstream: extractor.string("doh_upstream")?,
            dot_bootstrap: extractor.string("dot_bootstrap")?,
            proxy_listen_addr: extractor.string("proxy_listen_addr")?,
            proxy_listen_port: extractor.u16("proxy_listen_port")?,
            dnssec_enabled: extractor.bool("dnssec_enabled")?,
            dnssec_root_key: extractor.string_opt("dnssec_root_key"),
        })
    }
}

impl FromJson for WifiConfig {
    fn from_json(value: JsonValue) -> Result<Self> {
        let obj = value.as_object()
            .ok_or_else(|| err!(InvalidValue, "WifiConfig: expected object"))?;
        let extractor = FieldExtractor::new(obj, "WifiConfig");
        Ok(WifiConfig {
            ssid_24g: extractor.string("ssid_24g")?,
            ssid_5g: extractor.string("ssid_5g")?,
            country: extractor.string("country")?,
            isolate_guest: extractor.bool("isolate_guest")?,
            hidden_ssid: extractor.bool("hidden_ssid")?,
            max_assoc: extractor.u32("max_assoc")?,
        })
    }
}

impl FromJson for BuildConfig {
    fn from_json(value: JsonValue) -> Result<Self> {
        let obj = value.as_object()
            .ok_or_else(|| err!(InvalidValue, "BuildConfig: expected object"))?;
        let extractor = FieldExtractor::new(obj, "BuildConfig");
        Ok(BuildConfig {
            jobs: extractor.u32("jobs")?,
            verbose: extractor.bool("verbose")?,
            extra_packages: extractor.string_vec("extra_packages")?,
            exclude_packages: extractor.string_vec("exclude_packages")?,
            crypto_library: FromJson::from_json(obj.get("crypto_library")
                .ok_or_else(|| err!(InvalidValue, "BuildConfig.crypto_library: missing field"))?
                .clone())?,
        })
    }
}

impl FromJson for FeatureFlags {
    fn from_json(value: JsonValue) -> Result<Self> {
        let obj = value.as_object()
            .ok_or_else(|| err!(InvalidValue, "FeatureFlags: expected object"))?;
        let extractor = FieldExtractor::new(obj, "FeatureFlags");
        Ok(FeatureFlags {
            adblock_enabled: extractor.bool("adblock_enabled")?,
            banip_enabled: extractor.bool("banip_enabled")?,
            ipv6_enabled: extractor.bool("ipv6_enabled")?,
            vpn_enabled: extractor.bool("vpn_enabled")?,
        })
    }
}

impl FromJson for RadiusConfig {
    fn from_json(value: JsonValue) -> Result<Self> {
        let obj = value.as_object()
            .ok_or_else(|| err!(InvalidValue, "RadiusConfig: expected object"))?;
        let extractor = FieldExtractor::new(obj, "RadiusConfig");
        Ok(RadiusConfig {
            auth_port: extractor.u16("auth_port")?,
            acct_port: extractor.u16("acct_port")?,
            shared_secret: extractor.string_opt("shared_secret"),
            admin_password: extractor.string_opt("admin_password"),
        })
    }
}

impl FromJson for FirewallConfig {
    fn from_json(value: JsonValue) -> Result<Self> {
        let obj = value.as_object()
            .ok_or_else(|| err!(InvalidValue, "FirewallConfig: expected object"))?;
        let extractor = FieldExtractor::new(obj, "FirewallConfig");
        Ok(FirewallConfig {
            syn_flood_rate: extractor.u32("syn_flood_rate")?,
            conn_flood_rate: extractor.u32("conn_flood_rate")?,
            icmp_rate_limit: extractor.u32("icmp_rate_limit")?,
        })
    }
}

impl FromJson for SshConfig {
    fn from_json(value: JsonValue) -> Result<Self> {
        let obj = value.as_object()
            .ok_or_else(|| err!(InvalidValue, "SshConfig: expected object"))?;
        let extractor = FieldExtractor::new(obj, "SshConfig");
        Ok(SshConfig {
            idle_timeout: extractor.u32("idle_timeout")?,
            public_key: extractor.string_opt("public_key"),
            authorized_keys_path: extractor.string("authorized_keys_path")?,
        })
    }
}

impl FromJson for WebConfig {
    fn from_json(value: JsonValue) -> Result<Self> {
        let obj = value.as_object()
            .ok_or_else(|| err!(InvalidValue, "WebConfig: expected object"))?;
        let extractor = FieldExtractor::new(obj, "WebConfig");
        Ok(WebConfig {
            http_port: extractor.u16("http_port")?,
            https_port: extractor.u16("https_port")?,
            max_connections: extractor.u32("max_connections")?,
            admin_user: extractor.string("admin_user")?,
            admin_password_hash: extractor.string_opt("admin_password_hash"),
        })
    }
}

impl FromJson for VpnConfig {
    fn from_json(value: JsonValue) -> Result<Self> {
        let obj = value.as_object()
            .ok_or_else(|| err!(InvalidValue, "VpnConfig: expected object"))?;
        let extractor = FieldExtractor::new(obj, "VpnConfig");
        Ok(VpnConfig {
            wireguard_port: extractor.u16("wireguard_port")?,
            openvpn_port: extractor.u16("openvpn_port")?,
            wireguard_private_key: extractor.string_opt("wireguard_private_key"),
            wireguard_preshared_key: extractor.string_opt("wireguard_preshared_key"),
            openvpn_static_key: extractor.string_opt("openvpn_static_key"),
        })
    }
}

impl FromJson for StorageConfig {
    fn from_json(value: JsonValue) -> Result<Self> {
        let obj = value.as_object()
            .ok_or_else(|| err!(InvalidValue, "StorageConfig: expected object"))?;
        let extractor = FieldExtractor::new(obj, "StorageConfig");
        Ok(StorageConfig {
            usb_mount_point: extractor.string("usb_mount_point")?,
        })
    }
}

impl FromJson for TimeConfig {
    fn from_json(value: JsonValue) -> Result<Self> {
        let obj = value.as_object()
            .ok_or_else(|| err!(InvalidValue, "TimeConfig: expected object"))?;
        let extractor = FieldExtractor::new(obj, "TimeConfig");
        Ok(TimeConfig {
            timezone: extractor.string("timezone")?,
            ntp_servers: extractor.string_vec("ntp_servers")?,
            ntp_listen_addr: extractor.string("ntp_listen_addr")?,
            ntp_allow_network: extractor.string("ntp_allow_network")?,
        })
    }
}

impl FromJson for SecurityConfig {
    fn from_json(value: JsonValue) -> Result<Self> {
        let obj = value.as_object()
            .ok_or_else(|| err!(InvalidValue, "SecurityConfig: expected object"))?;
        let extractor = FieldExtractor::new(obj, "SecurityConfig");
        Ok(SecurityConfig {
            enable_kaslr: extractor.bool("enable_kaslr")?,
            enable_stack_protector: extractor.bool("enable_stack_protector")?,
            enable_pti: extractor.bool("enable_pti")?,
            enable_kernel_hardening: extractor.bool("enable_kernel_hardening")?,
            disable_module_loading: extractor.bool("disable_module_loading")?,
            enable_pointer_restrictions: extractor.bool("enable_pointer_restrictions")?,
            enable_refcount_hardening: extractor.bool("enable_refcount_hardening")?,
            enable_slab_hardening: extractor.bool("enable_slab_hardening")?,
            block_cloudflare_dns: extractor.bool("block_cloudflare_dns")?,
            block_telemetry_domains: extractor.string_vec("block_telemetry_domains")?,
            enable_dns_logging: extractor.bool("enable_dns_logging")?,
            enable_syn_cookies: extractor.bool("enable_syn_cookies")?,
            enable_rp_filter: extractor.bool("enable_rp_filter")?,
            enable_src_validation: extractor.bool("enable_src_validation")?,
            enable_icmp_ratelimit: extractor.bool("enable_icmp_ratelimit")?,
            enable_tcp_timestamp_protection: extractor.bool("enable_tcp_timestamp_protection")?,
            disable_core_dumps: extractor.bool("disable_core_dumps")?,
        })
    }
}

impl FromJson for SecretsConfig {
    fn from_json(value: JsonValue) -> Result<Self> {
        let obj = value.as_object()
            .ok_or_else(|| err!(InvalidValue, "SecretsConfig: expected object"))?;
        let extractor = FieldExtractor::new(obj, "SecretsConfig");
        Ok(SecretsConfig {
            radius_shared_secret: extractor.string_opt("radius_shared_secret"),
            radius_admin_password: extractor.string_opt("radius_admin_password"),
            ca_key_password: extractor.string_opt("ca_key_password"),
            server_key_password: extractor.string_opt("server_key_password"),
            root_password_hash: extractor.string_opt("root_password_hash"),
            ssh_public_key: extractor.string_opt("ssh_public_key"),
            wifi_radius_secret: extractor.string_opt("wifi_radius_secret"),
            wired_radius_secret: extractor.string_opt("wired_radius_secret"),
            wifi_24g_password: extractor.string_opt("wifi_24g_password"),
            wifi_5g_password: extractor.string_opt("wifi_5g_password"),
            encryption_key: extractor.string_opt("encryption_key"),
            hmac_key: extractor.string_opt("hmac_key"),
            ddns_api_key: extractor.string_opt("ddns_api_key"),
            cloudflare_api_token: extractor.string_opt("cloudflare_api_token"),
            cloudflare_zone_id: extractor.string_opt("cloudflare_zone_id"),
        })
    }
}

impl FromJson for CertificateConfig {
    fn from_json(value: JsonValue) -> Result<Self> {
        let obj = value.as_object()
            .ok_or_else(|| err!(InvalidValue, "CertificateConfig: expected object"))?;
        let extractor = FieldExtractor::new(obj, "CertificateConfig");
        Ok(CertificateConfig {
            country: extractor.string("country")?,
            state: extractor.string("state")?,
            locality: extractor.string("locality")?,
            organization: extractor.string("organization")?,
            organizational_unit: extractor.string("organizational_unit")?,
            common_name: extractor.string("common_name")?,
            email: extractor.string("email")?,
        })
    }
}

impl FromJson for OcfgConfig {
    fn from_json(value: JsonValue) -> Result<Self> {
        let obj = value.as_object()
            .ok_or_else(|| err!(InvalidValue, "OcfgConfig: expected object"))?;
        Ok(OcfgConfig {
            network: FromJson::from_json(obj.get("network")
                .ok_or_else(|| err!(InvalidValue, "OcfgConfig.network: missing field"))?
                .clone())?,
            dns: FromJson::from_json(obj.get("dns")
                .ok_or_else(|| err!(InvalidValue, "OcfgConfig.dns: missing field"))?
                .clone())?,
            wifi: FromJson::from_json(obj.get("wifi")
                .ok_or_else(|| err!(InvalidValue, "OcfgConfig.wifi: missing field"))?
                .clone())?,
            radius: FromJson::from_json(obj.get("radius")
                .ok_or_else(|| err!(InvalidValue, "OcfgConfig.radius: missing field"))?
                .clone())?,
            firewall: FromJson::from_json(obj.get("firewall")
                .ok_or_else(|| err!(InvalidValue, "OcfgConfig.firewall: missing field"))?
                .clone())?,
            ssh: FromJson::from_json(obj.get("ssh")
                .ok_or_else(|| err!(InvalidValue, "OcfgConfig.ssh: missing field"))?
                .clone())?,
            web: FromJson::from_json(obj.get("web")
                .ok_or_else(|| err!(InvalidValue, "OcfgConfig.web: missing field"))?
                .clone())?,
            vpn: FromJson::from_json(obj.get("vpn")
                .ok_or_else(|| err!(InvalidValue, "OcfgConfig.vpn: missing field"))?
                .clone())?,
            storage: FromJson::from_json(obj.get("storage")
                .ok_or_else(|| err!(InvalidValue, "OcfgConfig.storage: missing field"))?
                .clone())?,
            time: FromJson::from_json(obj.get("time")
                .ok_or_else(|| err!(InvalidValue, "OcfgConfig.time: missing field"))?
                .clone())?,
            build: FromJson::from_json(obj.get("build")
                .ok_or_else(|| err!(InvalidValue, "OcfgConfig.build: missing field"))?
                .clone())?,
            features: FromJson::from_json(obj.get("features")
                .ok_or_else(|| err!(InvalidValue, "OcfgConfig.features: missing field"))?
                .clone())?,
            security: FromJson::from_json(obj.get("security")
                .ok_or_else(|| err!(InvalidValue, "OcfgConfig.security: missing field"))?
                .clone())?,
            secrets: FromJson::from_json(obj.get("secrets")
                .ok_or_else(|| err!(InvalidValue, "OcfgConfig.secrets: missing field"))?
                .clone())?,
            certificates: FromJson::from_json(obj.get("certificates")
                .ok_or_else(|| err!(InvalidValue, "OcfgConfig.certificates: missing field"))?
                .clone())?,
        })
    }
}
