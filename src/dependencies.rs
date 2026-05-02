use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DependencyInfo {
    pub package: String,
    pub description: String,
    pub category: DependencyCategory,
    pub required_deps: Vec<String>,
    pub recommended_deps: Vec<String>,
    pub optional_deps: Vec<String>,
    pub kernel_deps: Vec<KernelDependency>,
    pub conflicts: Vec<String>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DependencyCategory {
    Network,
    Security,
    VPN,
    DNS,
    Filesystem,
    Storage,
    Wireless,
    Web,
    Utility,
    Kernel,
    Service,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelDependency {
    pub option: String,
    pub description: String,
    pub required: bool,
    pub recommended: bool,
}

pub struct DependencyKnowledgeBase {
    packages: HashMap<String, DependencyInfo>,
}

impl DependencyKnowledgeBase {
    pub fn new() -> Self {
        let mut packages = HashMap::new();
        
        // Initialize with known dependencies
        Self::initialize_adblock(&mut packages);
        Self::initialize_banip(&mut packages);
        Self::initialize_ntfs_support(&mut packages);
        Self::initialize_wireguard(&mut packages);
        Self::initialize_openvpn(&mut packages);
        Self::initialize_freeradius(&mut packages);
        Self::initialize_dnsproxy(&mut packages);
        Self::initialize_luci_apps(&mut packages);
        Self::initialize_filesystem_packages(&mut packages);
        Self::initialize_usb_packages(&mut packages);
        Self::initialize_wifi_packages(&mut packages);
        
        Self { packages }
    }

    fn initialize_adblock(packages: &mut HashMap<String, DependencyInfo>) {
        packages.insert("luci-app-adblock".to_string(), DependencyInfo {
            package: "luci-app-adblock".to_string(),
            description: "Ad-blocking module for LuCI interface".to_string(),
            category: DependencyCategory::DNS,
            required_deps: vec![
                "adblock".to_string(),
                "dnsmasq-full".to_string(),
                "wget".to_string(),
                "ca-certificates".to_string(),
            ],
            recommended_deps: vec![
                "tcpdump".to_string(),  // For DNS reporting and query logging
                "kmod-tcpdump".to_string(),  // Kernel module for tcpdump
                "coreutils".to_string(),  // For script utilities
                "coreutils-sort".to_string(),
            ],
            optional_deps: vec![
                "dnssec".to_string(),  // For DNSSEC validation support
                "kmod-dnssec".to_string(),
            ],
            kernel_deps: vec![
                KernelDependency {
                    option: "CONFIG_NETFILTER_XT_MATCH_STRING".to_string(),
                    description: "String matching in netfilter".to_string(),
                    required: false,
                    recommended: true,
                },
            ],
            conflicts: vec![
                "dnsmasq".to_string(),  // Conflicts with dnsmasq, needs dnsmasq-full
            ],
            notes: vec![
                "Requires persistent storage directory /etc/adblock".to_string(),
                "tcpdump is recommended for DNS query logging and reporting".to_string(),
                "DNSSEC support requires additional backend packages".to_string(),
                "Must use dnsmasq-full instead of dnsmasq".to_string(),
            ],
        });
    }

    fn initialize_banip(packages: &mut HashMap<String, DependencyInfo>) {
        packages.insert("luci-app-banip".to_string(), DependencyInfo {
            package: "luci-app-banip".to_string(),
            description: "IP blocking module for LuCI interface".to_string(),
            category: DependencyCategory::Security,
            required_deps: vec![
                "banip".to_string(),
                "wget".to_string(),
                "ca-certificates".to_string(),
                "firewall4".to_string(),
                "kmod-nft-core".to_string(),
                "kmod-nft-socket".to_string(),
            ],
            recommended_deps: vec![
                "curl".to_string(),  // Better than wget for some feeds
                "coreutils".to_string(),
                "coreutils-sort".to_string(),
            ],
            optional_deps: vec![
                "iptables-nft".to_string(),
            ],
            kernel_deps: vec![
                KernelDependency {
                    option: "CONFIG_NETFILTER_XT_MATCH_IPSET".to_string(),
                    description: "IP set matching support".to_string(),
                    required: false,
                    recommended: true,
                },
                KernelDependency {
                    option: "CONFIG_IP_SET".to_string(),
                    description: "IP set support".to_string(),
                    required: false,
                    recommended: true,
                },
            ],
            conflicts: vec![],
            notes: vec![
                "Requires persistent storage directory /etc/banip".to_string(),
                "Needs nftables (firewall4) not iptables".to_string(),
                "Feed authentication may be required for some sources".to_string(),
            ],
        });
    }

    fn initialize_ntfs_support(packages: &mut HashMap<String, DependencyInfo>) {
        packages.insert("kmod-fs-ntfs".to_string(), DependencyInfo {
            package: "kmod-fs-ntfs".to_string(),
            description: "NTFS filesystem kernel module".to_string(),
            category: DependencyCategory::Filesystem,
            required_deps: vec![
                "ntfs-3g".to_string(),  // Userspace NTFS driver - required for write support
            ],
            recommended_deps: vec![
                "ntfs-3g-lowntfs-3g".to_string(),  // Alternative NTFS-3G implementation
            ],
            optional_deps: vec![
                "kmod-fs-ntfs3".to_string(),  // Kernel NTFS3 driver (read-only, experimental)
            ],
            kernel_deps: vec![
                KernelDependency {
                    option: "CONFIG_NTFS_FS".to_string(),
                    description: "NTFS filesystem support".to_string(),
                    required: true,
                    recommended: false,
                },
                KernelDependency {
                    option: "CONFIG_NTFS_RW".to_string(),
                    description: "NTFS write support".to_string(),
                    required: false,
                    recommended: true,
                },
            ],
            conflicts: vec![],
            notes: vec![
                "kmod-fs-ntfs alone only provides read-only support".to_string(),
                "ntfs-3g is required for write support".to_string(),
                "ntfs-3g-lowntfs-3g may have better performance".to_string(),
                "Consider exFAT for better cross-platform compatibility".to_string(),
            ],
        });
    }

    fn initialize_wireguard(packages: &mut HashMap<String, DependencyInfo>) {
        packages.insert("wireguard-tools".to_string(), DependencyInfo {
            package: "wireguard-tools".to_string(),
            description: "WireGuard VPN userspace tools".to_string(),
            category: DependencyCategory::VPN,
            required_deps: vec![
                "kmod-wireguard".to_string(),
            ],
            recommended_deps: vec![
                "luci-app-wireguard".to_string(),
                "luci-app-vpn-policy-routing".to_string(),
            ],
            optional_deps: vec![
                "qrencode".to_string(),  // For QR code generation
            ],
            kernel_deps: vec![
                KernelDependency {
                    option: "CONFIG_WIREGUARD".to_string(),
                    description: "WireGuard secure network tunnel".to_string(),
                    required: true,
                    recommended: false,
                },
                KernelDependency {
                    option: "CONFIG_NETFILTER_XT_MATCH_POLICY".to_string(),
                    description: "Policy match support".to_string(),
                    required: false,
                    recommended: true,
                },
            ],
            conflicts: vec![],
            notes: vec![
                "Requires kernel with WireGuard support (CONFIG_WIREGUARD)".to_string(),
                "Recommended to use with policy routing for split tunneling".to_string(),
                "qrencode useful for mobile client configuration".to_string(),
            ],
        });
    }

    fn initialize_openvpn(packages: &mut HashMap<String, DependencyInfo>) {
        packages.insert("openvpn-openssl".to_string(), DependencyInfo {
            package: "openvpn-openssl".to_string(),
            description: "OpenVPN with OpenSSL crypto backend".to_string(),
            category: DependencyCategory::VPN,
            required_deps: vec![
                "libopenssl".to_string(),
                "libopenssl-conf".to_string(),
                "kmod-tun".to_string(),
            ],
            recommended_deps: vec![
                "luci-app-openvpn".to_string(),
                "luci-app-vpn-policy-routing".to_string(),
            ],
            optional_deps: vec![
                "openvpn-easy-rsa".to_string(),  // For PKI management
            ],
            kernel_deps: vec![
                KernelDependency {
                    option: "CONFIG_TUN".to_string(),
                    description: "Universal TUN/TAP device driver".to_string(),
                    required: true,
                    recommended: false,
                },
            ],
            conflicts: vec![
                "openvpn-mbedtls".to_string(),
                "openvpn-wolfssl".to_string(),
            ],
            notes: vec![
                "Crypto backend must match selected crypto library".to_string(),
                "easy-rsa recommended for certificate management".to_string(),
                "Policy routing recommended for split tunneling".to_string(),
            ],
        });
    }

    fn initialize_freeradius(packages: &mut HashMap<String, DependencyInfo>) {
        packages.insert("freeradius3".to_string(), DependencyInfo {
            package: "freeradius3".to_string(),
            description: "FreeRADIUS3 server for 802.1X authentication".to_string(),
            category: DependencyCategory::Security,
            required_deps: vec![
                "libopenssl".to_string(),  // Or mbedtls/wolfssl depending on selection
                "hostapd-openssl".to_string(),  // Or hostapd-mbedtls/wolfssl
            ],
            recommended_deps: vec![
                "luci-app-freeradius".to_string(),
                "python3".to_string(),  // For some scripts
            ],
            optional_deps: vec![
                "freeradius3-mod-eap".to_string(),
                "freeradius3-mod-peap".to_string(),
                "freeradius3-mod-ttls".to_string(),
            ],
            kernel_deps: vec![
                KernelDependency {
                    option: "CONFIG_CRYPTO_USER_API".to_string(),
                    description: "Userspace cryptographic API".to_string(),
                    required: false,
                    recommended: true,
                },
            ],
            conflicts: vec![],
            notes: vec![
                "Crypto library must match between freeradius3 and hostapd".to_string(),
                "Requires certificate generation for EAP-TLS".to_string(),
                "PEAP/TTLS require password authentication setup".to_string(),
            ],
        });
    }

    fn initialize_dnsproxy(packages: &mut HashMap<String, DependencyInfo>) {
        packages.insert("dnsproxy".to_string(), DependencyInfo {
            package: "dnsproxy".to_string(),
            description: "DNS-over-HTTPS/HTTPS proxy".to_string(),
            category: DependencyCategory::DNS,
            required_deps: vec![
                "ca-certificates".to_string(),
            ],
            recommended_deps: vec![
                "dnsmasq-full".to_string(),
            ],
            optional_deps: vec![
                "kmod-tun".to_string(),  // For some advanced features
            ],
            kernel_deps: vec![],
            conflicts: vec![],
            notes: vec![
                "Requires upstream DoH/DoT server configuration".to_string(),
                "Best used with dnsmasq-full for local DNS caching".to_string(),
                "Supports multiple upstream servers".to_string(),
            ],
        });
    }

    fn initialize_luci_apps(packages: &mut HashMap<String, DependencyInfo>) {
        // luci-app-statistics
        packages.insert("luci-app-statistics".to_string(), DependencyInfo {
            package: "luci-app-statistics".to_string(),
            description: "LuCI statistics collection interface".to_string(),
            category: DependencyCategory::Web,
            required_deps: vec![
                "collectd".to_string(),
            ],
            recommended_deps: vec![
                "collectd-mod-cpu".to_string(),
                "collectd-mod-memory".to_string(),
                "collectd-mod-interface".to_string(),
                "collectd-mod-iptables".to_string(),
                "collectd-mod-load".to_string(),
            ],
            optional_deps: vec![
                "collectd-mod-dns".to_string(),
                "collectd-mod-wireless".to_string(),
                "collectd-mod-thermal".to_string(),
            ],
            kernel_deps: vec![],
            conflicts: vec![],
            notes: vec![
                "Add specific collectd modules for desired metrics".to_string(),
                "Requires rrdtool for graphing".to_string(),
            ],
        });

        // luci-app-ttyd
        packages.insert("luci-app-ttyd".to_string(), DependencyInfo {
            package: "luci-app-ttyd".to_string(),
            description: "LuCI web terminal interface".to_string(),
            category: DependencyCategory::Web,
            required_deps: vec![
                "ttyd".to_string(),
                "uhttpd".to_string(),
            ],
            recommended_deps: vec![
                "luci-mod-admin-full".to_string(),
            ],
            optional_deps: vec![],
            kernel_deps: vec![],
            conflicts: vec![],
            notes: vec![
                "Requires HTTPS on uhttpd for secure terminal access".to_string(),
                "Uses LuCI authentication".to_string(),
            ],
        });
    }

    fn initialize_filesystem_packages(packages: &mut HashMap<String, DependencyInfo>) {
        // exFAT support
        packages.insert("kmod-fs-exfat".to_string(), DependencyInfo {
            package: "kmod-fs-exfat".to_string(),
            description: "exFAT filesystem kernel module".to_string(),
            category: DependencyCategory::Filesystem,
            required_deps: vec![
                "exfat-utils".to_string(),
            ],
            recommended_deps: vec![
                "exfat-fuse".to_string(),
            ],
            optional_deps: vec![],
            kernel_deps: vec![
                KernelDependency {
                    option: "CONFIG_EXFAT_FS".to_string(),
                    description: "exFAT filesystem support".to_string(),
                    required: true,
                    recommended: false,
                },
            ],
            conflicts: vec![],
            notes: vec![
                "Better cross-platform compatibility than NTFS".to_string(),
                "No file size limitations like FAT32".to_string(),
            ],
        });

        // ext4 support
        packages.insert("kmod-fs-ext4".to_string(), DependencyInfo {
            package: "kmod-fs-ext4".to_string(),
            description: "EXT4 filesystem kernel module".to_string(),
            category: DependencyCategory::Filesystem,
            required_deps: vec![
                "e2fsprogs".to_string(),
            ],
            recommended_deps: vec![
                "resize2fs".to_string(),
                "tune2fs".to_string(),
            ],
            optional_deps: vec![
                "e2fsprogs".to_string(),
            ],
            kernel_deps: vec![
                KernelDependency {
                    option: "CONFIG_EXT4_FS".to_string(),
                    description: "EXT4 filesystem support".to_string(),
                    required: true,
                    recommended: false,
                },
            ],
            conflicts: vec![],
            notes: vec![
                "Native Linux filesystem with journaling".to_string(),
                "Best performance on Linux systems".to_string(),
            ],
        });
    }

    fn initialize_usb_packages(packages: &mut HashMap<String, DependencyInfo>) {
        // USB storage
        packages.insert("kmod-usb-storage".to_string(), DependencyInfo {
            package: "kmod-usb-storage".to_string(),
            description: "USB storage kernel module".to_string(),
            category: DependencyCategory::Storage,
            required_deps: vec![
                "kmod-usb-core".to_string(),
            ],
            recommended_deps: vec![
                "block-mount".to_string(),
                "kmod-scsi-core".to_string(),
            ],
            optional_deps: vec![
                "kmod-usb-storage-uas".to_string(),  // UAS protocol support
            ],
            kernel_deps: vec![
                KernelDependency {
                    option: "CONFIG_USB_STORAGE".to_string(),
                    description: "USB Mass Storage support".to_string(),
                    required: true,
                    recommended: false,
                },
                KernelDependency {
                    option: "CONFIG_SCSI".to_string(),
                    description: "SCSI disk support".to_string(),
                    required: true,
                    recommended: false,
                },
            ],
            conflicts: vec![],
            notes: vec![
                "Required for USB drive support".to_string(),
                "UAS recommended for better performance".to_string(),
                "block-mount required for auto-mounting".to_string(),
            ],
        });

        // USB network
        packages.insert("kmod-usb-net".to_string(), DependencyInfo {
            package: "kmod-usb-net".to_string(),
            description: "USB network kernel modules".to_string(),
            category: DependencyCategory::Network,
            required_deps: vec![
                "kmod-usb-core".to_string(),
            ],
            recommended_deps: vec![
                "kmod-usb-net-cdc-ether".to_string(),
                "kmod-usb-net-rndis".to_string(),
            ],
            optional_deps: vec![
                "kmod-usb-net-cdc-mbim".to_string(),
                "kmod-usb-net-cdc-ncm".to_string(),
                "kmod-usb-net-qmi-wwan".to_string(),
            ],
            kernel_deps: vec![
                KernelDependency {
                    option: "CONFIG_USB_NET_DRIVERS".to_string(),
                    description: "USB network device support".to_string(),
                    required: true,
                    recommended: false,
                },
            ],
            conflicts: vec![],
            notes: vec![
                "Supports USB Ethernet and WWAN dongles".to_string(),
                "CDC-ether and RNDIS most common for Ethernet dongles".to_string(),
                "MBIM/NCM/QMI for cellular modems".to_string(),
            ],
        });
    }

    fn initialize_wifi_packages(packages: &mut HashMap<String, DependencyInfo>) {
        // hostapd
        packages.insert("hostapd-openssl".to_string(), DependencyInfo {
            package: "hostapd-openssl".to_string(),
            description: "Host AP daemon with OpenSSL crypto".to_string(),
            category: DependencyCategory::Wireless,
            required_deps: vec![
                "libopenssl".to_string(),
                "libubus".to_string(),
                "libucode".to_string(),
            ],
            recommended_deps: vec![
                "wpa-supplicant-openssl".to_string(),
                "luci-app-wifisettings".to_string(),
            ],
            optional_deps: vec![
                "hostapd-utils".to_string(),
            ],
            kernel_deps: vec![
                KernelDependency {
                    option: "CONFIG_CFG80211".to_string(),
                    description: "Wireless configuration API".to_string(),
                    required: true,
                    recommended: false,
                },
                KernelDependency {
                    option: "CONFIG_MAC80211".to_string(),
                    description: "IEEE 802.11 wireless LAN".to_string(),
                    required: true,
                    recommended: false,
                },
            ],
            conflicts: vec![
                "hostapd-mbedtls".to_string(),
                "hostapd-wolfssl".to_string(),
                "wpad-openssl".to_string(),
                "wpad-mbedtls".to_string(),
                "wpad-wolfssl".to_string(),
            ],
            notes: vec![
                "Crypto backend must match selected crypto library".to_string(),
                "Required for Enterprise 802.1X authentication".to_string(),
                "Conflicts with wpad (use one or the other)".to_string(),
            ],
        });

        // wpad
        packages.insert("wpad-openssl".to_string(), DependencyInfo {
            package: "wpad-openssl".to_string(),
            description: "WPA supplicant with OpenSSL crypto".to_string(),
            category: DependencyCategory::Wireless,
            required_deps: vec![
                "libopenssl".to_string(),
                "libubus".to_string(),
                "libucode".to_string(),
            ],
            recommended_deps: vec![
                "luci-app-wifisettings".to_string(),
            ],
            optional_deps: vec![],
            kernel_deps: vec![
                KernelDependency {
                    option: "CONFIG_CFG80211".to_string(),
                    description: "Wireless configuration API".to_string(),
                    required: true,
                    recommended: false,
                },
                KernelDependency {
                    option: "CONFIG_MAC80211".to_string(),
                    description: "IEEE 802.11 wireless LAN".to_string(),
                    required: true,
                    recommended: false,
                },
            ],
            conflicts: vec![
                "wpad-mbedtls".to_string(),
                "wpad-wolfssl".to_string(),
                "hostapd-openssl".to_string(),
                "hostapd-mbedtls".to_string(),
                "hostapd-wolfssl".to_string(),
            ],
            notes: vec![
                "Crypto backend must match selected crypto library".to_string(),
                "Simpler than hostapd, for client/STA mode only".to_string(),
                "Conflicts with hostapd (use one or the other)".to_string(),
            ],
        });
    }

    pub fn get_package_info(&self, package: &str) -> Option<&DependencyInfo> {
        self.packages.get(package)
    }

    pub fn all_packages(&self) -> Vec<&DependencyInfo> {
        self.packages.values().collect()
    }

    pub fn check_dependencies(
        &self,
        installed_packages: &HashSet<String>,
        kernel_config: &HashMap<String, String>,
    ) -> DependencyCheckResult {
        let mut missing_required = Vec::new();
        let mut missing_recommended = Vec::new();
        let mut missing_kernel = Vec::new();
        let mut conflicts_found = Vec::new();

        for package in installed_packages {
            if let Some(info) = self.get_package_info(package) {
                // Check required dependencies
                for dep in &info.required_deps {
                    if !installed_packages.contains(dep) {
                        missing_required.push(MissingDependency {
                            package: package.clone(),
                            missing: dep.clone(),
                            dependency_type: DependencyType::Required,
                        });
                    }
                }

                // Check recommended dependencies
                for dep in &info.recommended_deps {
                    if !installed_packages.contains(dep) {
                        missing_recommended.push(MissingDependency {
                            package: package.clone(),
                            missing: dep.clone(),
                            dependency_type: DependencyType::Recommended,
                        });
                    }
                }

                // Check kernel dependencies
                for kernel_dep in &info.kernel_deps {
                    if kernel_dep.required || kernel_dep.recommended {
                        if !kernel_config.contains_key(&kernel_dep.option) {
                            missing_kernel.push(MissingKernelOption {
                                package: package.clone(),
                                option: kernel_dep.option.clone(),
                                description: kernel_dep.description.clone(),
                                required: kernel_dep.required,
                            });
                        }
                    }
                }

                // Check conflicts
                for conflict in &info.conflicts {
                    if installed_packages.contains(conflict) {
                        conflicts_found.push(Conflict {
                            package1: package.clone(),
                            package2: conflict.clone(),
                        });
                    }
                }
            }
        }

        DependencyCheckResult {
            missing_required,
            missing_recommended,
            missing_kernel,
            conflicts_found,
        }
    }
}

#[derive(Debug, Clone)]
pub struct MissingDependency {
    pub package: String,
    pub missing: String,
    pub dependency_type: DependencyType,
}

#[derive(Debug, Clone)]
pub enum DependencyType {
    Required,
    Recommended,
    Optional,
}

#[derive(Debug, Clone)]
pub struct MissingKernelOption {
    pub package: String,
    pub option: String,
    pub description: String,
    pub required: bool,
}

#[derive(Debug, Clone)]
pub struct Conflict {
    pub package1: String,
    pub package2: String,
}

#[derive(Debug, Clone)]
pub struct DependencyCheckResult {
    pub missing_required: Vec<MissingDependency>,
    pub missing_recommended: Vec<MissingDependency>,
    pub missing_kernel: Vec<MissingKernelOption>,
    pub conflicts_found: Vec<Conflict>,
}

impl DependencyCheckResult {
    pub fn has_errors(&self) -> bool {
        !self.missing_required.is_empty() || !self.conflicts_found.is_empty()
    }

    pub fn has_warnings(&self) -> bool {
        !self.missing_recommended.is_empty() || !self.missing_kernel.is_empty()
    }

    pub fn is_clean(&self) -> bool {
        !self.has_errors() && !self.has_warnings()
    }
}

impl Default for DependencyKnowledgeBase {
    fn default() -> Self {
        Self::new()
    }
}
