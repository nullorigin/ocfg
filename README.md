# ocfg - OpenWrt Configuration Tool

A comprehensive Rust-based configuration tool for OpenWrt routers that automates the many steps needed to configure OpenWrt, including authentication setup, secret generation, package configuration, kernel module selection, and security hardening.

## Features

- **Interactive and Non-Interactive Modes**: Run with a guided wizard or use configuration files for automation
- **Comprehensive Configuration**: Handle network, DNS, Wi-Fi, RADIUS, firewall, VPN, storage, and time settings
- **Secret Generation**: Automatically generate cryptographically secure secrets for RADIUS, certificates, VPNs, and encryption keys
- **Security Hardening**: Apply kernel hardening, firewall rules, sysctl configurations, and best practices
- **Template-Based**: Generate OpenWrt configuration files using Handlebars templates
- **Validation**: Validate configuration syntax, required values, and secret security
- **Multiple Export Formats**: Export configuration to ENV, JSON, YAML, or TOML formats
- **Crypto Library Selection**: Choose between OpenSSL, MbedTLS, or WolfSSL for TLS/crypto operations
- **Dependency Checking**: Comprehensive dependency checker with required and recommended dependencies
- **Kernel Dependency Validation**: Check kernel configuration options for package compatibility
- **Wiki Integration**: Fetch and update dependency information from OpenWrt wiki

## Installation

### From Source

```bash
cargo install --path .
```

### From Crates.io (when published)

```bash
cargo install ocfg
```

## Quick Start

### Interactive Mode

Initialize a new configuration with the interactive wizard:

```bash
ocfg init
```

### Non-Interactive Mode

Use defaults or load from an existing configuration file:

```bash
ocfg init --non-interactive
```

Or specify a configuration file:

```bash
ocfg init --config /path/to/config.toml --non-interactive
```

## Usage

### Initialization

```bash
# Initialize with interactive wizard
ocfg init

# Initialize with specific profile and target
ocfg init --profile enterprise --target linksys_e8450

# Non-interactive mode
ocfg init --non-interactive
```

### Secret Generation

```bash
# Generate all secrets
ocfg generate-secrets --all

# Generate specific secret types
ocfg generate-secrets --radius --certificates

# Specify output directory
ocfg generate-secrets --all --output /path/to/secrets
```

### Authentication Configuration

```bash
# Configure all authentication
ocfg config-auth --all

# Configure specific authentication methods
ocfg config-auth --radius --ssh
```

### Network Configuration

```bash
# Configure all network settings
ocfg config-network --all

# Configure specific network components
ocfg config-network --wifi --vpn
```

### Security Configuration

```bash
# Configure all security settings
ocfg config-security --all

# Configure specific security components
ocfg config-security --dns --kernel
```

### Package Management

```bash
# List available packages
ocfg config-packages --list

# Add packages
ocfg config-packages --add luci-app-statistics luci-app-nut

# Remove packages
ocfg config-packages --remove luci-app-adblock

# Configure kernel modules
ocfg config-packages --kernel
```

### Dependency Checking

```bash
# Check dependencies for configured packages
ocfg check-dependencies

# Check specific packages
ocfg check-dependencies --packages luci-app-adblock wireguard-tools

# Check all known packages
ocfg check-dependencies --all

# Show recommended dependencies
ocfg check-dependencies --recommended

# Check with kernel config
ocfg check-dependencies --kernel-config /path/to/kernel.config

# Attempt to fix missing dependencies
ocfg check-dependencies --fix

# Update dependency information from OpenWrt wiki
ocfg check-dependencies --update-from-wiki
```

### Service Configuration

```bash
# Configure all services
ocfg config-services --all

# Configure specific services
ocfg config-services --dns-proxy --ntp
```

### Validation

```bash
# Run all validation checks
ocfg validate --all

# Run specific checks
ocfg validate --syntax --secrets
```

### Export Configuration

```bash
# Export to various formats
ocfg export --format env --output openwrt-config.env
ocfg export --format json --output config.json
ocfg export --format yaml
ocfg export --format toml
```

### Apply to OpenWrt Build

```bash
# Apply configuration to OpenWrt source tree
ocfg apply --openwrt-dir /path/to/openwrt-25.12.2

# Dry run to preview changes
ocfg apply --openwrt-dir /path/to/openwrt-25.12.2 --dry-run
```

## Configuration Files

ocfg uses two main configuration files:

### config.toml

Main configuration file containing network, DNS, Wi-Fi, firewall, and other settings. Located at:
- Linux: `~/.config/ocfg/config.toml`
- Default: `./ocfg.toml` (if config directory doesn't exist)

### secrets.toml

Sensitive configuration file containing passwords, keys, and other secrets. Located at:
- Linux: `~/.config/ocfg/secrets.toml`
- Default: `./secrets.toml` (if config directory doesn't exist)

**Security Note**: The secrets file should have restrictive permissions (600) and never be committed to version control.

## Configuration Options

### Network

- `wan_interface`: WAN physical interface name (default: `wan`)
- `lan_interface`: LAN bridge interface name (default: `br-lan`)

### DNS

- `doh_upstream`: DNS over HTTPS upstream (default: `https://dns.quad9.net/dns-query`)
- `dot_bootstrap`: DNS over TLS bootstrap (default: `9.9.9.9:853`)
- `dnssec_enabled`: Enable DNSSEC validation (default: `true`)

### Wi-Fi

- `ssid_24g`: 2.4GHz SSID (default: `Enterprise-2.4G`)
- `ssid_5g`: 5GHz SSID (default: `Enterprise-5G`)
- `country`: Country code (default: `US`)
- `isolate_guest`: Client isolation (default: `false`)

### RADIUS

- `auth_port`: Authentication port (default: `1812`)
- `acct_port`: Accounting port (default: `1813`)
- `shared_secret`: RADIUS shared secret (auto-generated if not set)

### Security

- `enable_kaslr`: Enable kernel address space layout randomization (default: `true`)
- `enable_stack_protector`: Enable kernel stack protector (default: `true`)
- `enable_pti`: Enable page table isolation (default: `true`)
- `syn_flood_rate`: SYN flood rate limit (default: `20`)

### Crypto Library

- `crypto_library`: Choose TLS/crypto library
  - `openssl` (default): Best compatibility, widely used
  - `mbedtls`: Smaller footprint, suitable for embedded devices
  - `wolfssl`: Small footprint, FIPS certified options

## Dependency Checking

ocfg includes a comprehensive dependency checker that validates:

- **Required Dependencies**: Packages that must be present for functionality
- **Recommended Dependencies**: Packages that enhance functionality but aren't strictly required
- **Kernel Dependencies**: Kernel configuration options needed for package compatibility
- **Package Conflicts**: Detects conflicting package combinations

### Example Dependency Issues Detected

- `luci-app-adblock` requires `tcpdump` for DNS reporting and `dnsmasq-full` for DNSSEC support
- `kmod-fs-ntfs` requires `ntfs-3g` for write support (kernel module alone is read-only)
- `wireguard-tools` requires `kmod-wireguard` kernel module
- Crypto library consistency between related packages (e.g., `openvpn-openssl` vs `openvpn-mbedtls`)

### Dependency Knowledge Base

The tool includes a built-in knowledge base with dependency information for common OpenWrt packages:

- **Network Services**: DNS, VPN, firewall packages
- **Filesystem Support**: NTFS, exFAT, ext4 with required userspace tools
- **Wireless**: hostapd, wpad variants with crypto library requirements
- **Security Tools**: adblock, banIP with reporting dependencies
- **Storage**: USB storage, network dongles with required kernel modules
- **Web Interface**: LuCI applications with their dependencies

### Features

- `adblock_enabled`: Enable ad blocking (default: `true`)
- `banip_enabled`: Enable IP blocking (default: `true`)
- `ipv6_enabled`: Enable IPv6 (default: `false`)

## Generated Files

When applying configuration to an OpenWrt build, ocfg generates:

- `setup-config.env`: Environment variable configuration file
- `setup-secrets.env`: Sensitive secrets configuration file
- `files/etc/nftables.d/10-hardening.nft`: nftables hardening rules
- `files/etc/sysctl.d/20-hardening.conf`: sysctl security settings
- `package/network/services/dnsmasq/files/dhcp.conf`: dnsmasq DNS/DHCP configuration
- `package/network/config/firewall/files/firewall.config`: firewall configuration

## Development

### Building

```bash
cargo build --release
```

### Running Tests

```bash
cargo test
```

### Linting

```bash
cargo clippy
```

### Formatting

```bash
cargo fmt
```

## Security Considerations

- Secrets are stored in a separate file with restrictive permissions
- Auto-generated secrets use cryptographically secure random number generation
- Configuration validation checks for weak secrets and missing required values
- Never commit `secrets.toml` or `setup-secrets.env` to version control

## License

MIT License - see LICENSE file for details

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Acknowledgments

This tool is inspired by the comprehensive OpenWrt configuration scripts for the Linksys E8450 UBI, particularly the setup-build.sh script and associated configuration files.

## Support

For issues, questions, or contributions, please visit the GitHub repository at https://github.com/nullorigin/ocfg.git
