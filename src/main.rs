use anyhow::Result;
use clap::{Parser, Subcommand};
use log::info;

#[derive(Parser)]
#[command(name = "ocfg")]
#[command(about = "OpenWrt Configuration Tool - Automated configuration for OpenWrt routers", long_about = None)]
#[command(version = "0.1.0")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Enable verbose logging
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Configuration file path (default: ./ocfg.toml)
    #[arg(short, long, global = true)]
    config: Option<String>,

    /// Non-interactive mode (use defaults or config file)
    #[arg(short, long, global = true)]
    non_interactive: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new configuration
    Init {
        /// Configuration profile to use
        #[arg(short, long)]
        profile: Option<String>,

        /// Target device model
        #[arg(short, long)]
        target: Option<String>,
    },

    /// Generate secrets and credentials
    GenerateSecrets {
        /// Output directory for secrets
        #[arg(short, long)]
        output: Option<String>,

        /// Generate RADIUS secrets
        #[arg(long)]
        radius: bool,

        /// Generate certificate secrets
        #[arg(long)]
        certificates: bool,

        /// Generate VPN secrets
        #[arg(long)]
        vpn: bool,

        /// Generate all secrets
        #[arg(long)]
        all: bool,
    },

    /// Configure authentication settings
    ConfigAuth {
        /// Configure RADIUS authentication
        #[arg(long)]
        radius: bool,

        /// Configure SSH authentication
        #[arg(long)]
        ssh: bool,

        /// Configure web interface authentication
        #[arg(long)]
        web: bool,

        /// Configure all authentication
        #[arg(long)]
        all: bool,
    },

    /// Configure network settings
    ConfigNetwork {
        /// Configure WAN interface
        #[arg(long)]
        wan: bool,

        /// Configure LAN interface
        #[arg(long)]
        lan: bool,

        /// Configure Wi-Fi settings
        #[arg(long)]
        wifi: bool,

        /// Configure VPN settings
        #[arg(long)]
        vpn: bool,

        /// Configure all network settings
        #[arg(long)]
        all: bool,
    },

    /// Configure DNS and firewall settings
    ConfigSecurity {
        /// Configure DNS settings
        #[arg(long)]
        dns: bool,

        /// Configure firewall rules
        #[arg(long)]
        firewall: bool,

        /// Configure kernel hardening
        #[arg(long)]
        kernel: bool,

        /// Configure all security settings
        #[arg(long)]
        all: bool,
    },

    /// Configure packages and kernel modules
    ConfigPackages {
        /// List available packages
        #[arg(long)]
        list: bool,

        /// Add package
        #[arg(long)]
        add: Vec<String>,

        /// Remove package
        #[arg(long)]
        remove: Vec<String>,

        /// Configure kernel modules
        #[arg(long)]
        kernel: bool,
    },

    /// Check package dependencies
    CheckDependencies {
        /// Check specific packages
        #[arg(short, long)]
        packages: Vec<String>,

        /// Check all known packages
        #[arg(long)]
        all: bool,

        /// Path to kernel config file
        #[arg(short, long)]
        kernel_config: Option<String>,

        /// Show recommended dependencies
        #[arg(long)]
        recommended: bool,

        /// Attempt to fix missing dependencies
        #[arg(long)]
        fix: bool,

        /// Update dependency information from OpenWrt wiki
        #[arg(long)]
        update_from_wiki: bool,
    },

    /// Configure services
    ConfigServices {
        /// Configure DNS proxy
        #[arg(long)]
        dns_proxy: bool,

        /// Configure ad blocking
        #[arg(long)]
        adblock: bool,

        /// Configure IP blocking
        #[arg(long)]
        banip: bool,

        /// Configure NTP service
        #[arg(long)]
        ntp: bool,

        /// Configure all services
        #[arg(long)]
        all: bool,
    },

    /// Validate current configuration
    Validate {
        /// Check configuration syntax
        #[arg(long)]
        syntax: bool,

        /// Check for missing required values
        #[arg(long)]
        required: bool,

        /// Check secret security
        #[arg(long)]
        secrets: bool,

        /// Run all validation checks
        #[arg(long)]
        all: bool,
    },

    /// Export configuration to various formats
    Export {
        /// Output format (env, json, yaml, toml)
        #[arg(short, long)]
        format: String,

        /// Output file path
        #[arg(short, long)]
        output: Option<String>,
    },

    /// Apply configuration to OpenWrt build
    Apply {
        /// OpenWrt source directory
        #[arg(short, long)]
        openwrt_dir: String,

        /// Dry run (show changes without applying)
        #[arg(long)]
        dry_run: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    if cli.verbose {
        env_logger::Builder::from_default_env()
            .filter_level(log::LevelFilter::Debug)
            .init();
    } else {
        env_logger::Builder::from_default_env()
            .filter_level(log::LevelFilter::Info)
            .init();
    }

    info!("OpenWrt Configuration Tool starting...");

    match cli.command {
        Commands::Init { profile, target } => {
            ocfg::commands::init::run(profile, target, cli.non_interactive).await?;
        }
        Commands::GenerateSecrets {
            output,
            radius,
            certificates,
            vpn,
            all,
        } => {
            ocfg::commands::secrets::run(output, radius, certificates, vpn, all, cli.non_interactive).await?;
        }
        Commands::ConfigAuth {
            radius,
            ssh,
            web,
            all,
        } => {
            ocfg::commands::auth::run(radius, ssh, web, all, cli.non_interactive).await?;
        }
        Commands::ConfigNetwork {
            wan,
            lan,
            wifi,
            vpn,
            all,
        } => {
            ocfg::commands::network::run(wan, lan, wifi, vpn, all, cli.non_interactive).await?;
        }
        Commands::ConfigSecurity {
            dns,
            firewall,
            kernel,
            all,
        } => {
            ocfg::commands::security::run(dns, firewall, kernel, all, cli.non_interactive).await?;
        }
        Commands::ConfigPackages {
            list,
            add,
            remove,
            kernel,
        } => {
            ocfg::commands::packages::run(list, add, remove, kernel, cli.non_interactive).await?;
        }
        Commands::CheckDependencies {
            packages,
            all,
            kernel_config,
            recommended,
            fix,
            update_from_wiki,
        } => {
            ocfg::commands::dependencies::run(packages, all, kernel_config, recommended, fix, update_from_wiki).await?;
        }
        Commands::ConfigServices {
            dns_proxy,
            adblock,
            banip,
            ntp,
            all,
        } => {
            ocfg::commands::services::run(dns_proxy, adblock, banip, ntp, all, cli.non_interactive).await?;
        }
        Commands::Validate {
            syntax,
            required,
            secrets,
            all,
        } => {
            ocfg::commands::validate::run(syntax, required, secrets, all).await?;
        }
        Commands::Export { format, output } => {
            ocfg::commands::export::run(format, output).await?;
        }
        Commands::Apply {
            openwrt_dir,
            dry_run,
        } => {
            ocfg::commands::apply::run(openwrt_dir, dry_run).await?;
        }
    }

    Ok(())
}
