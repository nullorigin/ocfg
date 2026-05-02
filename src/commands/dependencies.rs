use crate::config::OcfgConfig;
use crate::dependencies::{DependencyKnowledgeBase, DependencyCheckResult};
use crate::error::Result;
use crate::err;
use crate::wiki_parser::OpenWrtWikiParser;
use std::collections::{HashMap, HashSet};
use std::fs;

pub async fn run(
    check_packages: Vec<String>,
    check_all: bool,
    kernel_config: Option<String>,
    show_recommended: bool,
    fix: bool,
    update_from_wiki: bool,
) -> Result<()> {
    println!("Running dependency checker...");

    let config = OcfgConfig::load()?;
    let knowledge_base = DependencyKnowledgeBase::new();

    // Get packages to check
    let packages_to_check = if check_all {
        knowledge_base.all_packages().iter().map(|p| p.package.clone()).collect()
    } else if check_packages.is_empty() {
        // Use packages from config
        let mut packages = HashSet::new();
        packages.extend(config.build.extra_packages.clone());
        
        // Add common packages based on features
        if config.features.adblock_enabled {
            packages.insert("luci-app-adblock".to_string());
        }
        if config.features.banip_enabled {
            packages.insert("luci-app-banip".to_string());
        }
        
        // Add crypto library packages
        match config.build.crypto_library {
            crate::config::CryptoLibrary::OpenSSL => {
                packages.insert("libopenssl".to_string());
                packages.insert("libopenssl-conf".to_string());
            }
            crate::config::CryptoLibrary::MbedTLS => {
                packages.insert("libmbedtls".to_string());
            }
            crate::config::CryptoLibrary::WolfSSL => {
                packages.insert("libwolfssl".to_string());
            }
        }
        
        packages.into_iter().collect()
    } else {
        check_packages.clone()
    };

    // Load kernel config if provided
    let kernel_config_map = if let Some(kernel_config_path) = kernel_config {
        load_kernel_config(&kernel_config_path)?
    } else {
        HashMap::new()
    };

    let installed_packages: HashSet<String> = packages_to_check.into_iter().collect();

    // Run dependency check
    let result = knowledge_base.check_dependencies(&installed_packages, &kernel_config_map);

    // Display results
    display_results(&result, show_recommended);

    // Fix if requested
    if fix {
        if let Err(e) = fix_dependencies(&config, &result, &knowledge_base).await {
            println!("Error fixing dependencies: {}", e);
        }
    }

    // Update from wiki if requested
    if update_from_wiki {
        update_dependencies_from_wiki(&check_packages, &knowledge_base).await?;
    }

    if result.has_errors() {
        Err(err!(Validation, "Dependency check failed with errors"))
    } else {
        Ok(())
    }
}

async fn update_dependencies_from_wiki(
    packages: &[String],
    _knowledge_base: &DependencyKnowledgeBase,
) -> Result<()> {
    println!("\n=== Updating Dependencies from OpenWrt Wiki ===\n");

    let parser = OpenWrtWikiParser::new()?;
    let packages_to_fetch = if packages.is_empty() {
        // Fetch a set of common packages
        vec![
            "luci-app-adblock".to_string(),
            "luci-app-banip".to_string(),
            "wireguard-tools".to_string(),
            "openvpn-openssl".to_string(),
            "kmod-fs-ntfs".to_string(),
        ]
    } else {
        packages.to_vec()
    };

    for package in &packages_to_fetch {
        println!("Fetching wiki page for: {}", package);
        
        match parser.fetch_package_page(package).await {
            Ok(content) => {
                match parser.parse_dependencies(&content, package) {
                    Ok(dep_info) => {
                        println!("  ✓ Successfully parsed dependencies for {}", package);
                        println!("    Required: {}", dep_info.required_deps.join(", "));
                        println!("    Recommended: {}", dep_info.recommended_deps.join(", "));
                        
                        // In a real implementation, this would update the knowledge base
                        // For now, we just display the information
                    }
                    Err(e) => {
                        println!("  ✗ Failed to parse dependencies: {}", e);
                    }
                }
            }
            Err(e) => {
                println!("  ✗ Failed to fetch wiki page: {}", e);
            }
        }
    }

    println!("\nWiki update complete. This feature would update the dependency knowledge base with the latest information from the OpenWrt wiki.");
    println!("Note: This is a demonstration. The knowledge base currently uses hardcoded dependency information.");

    Ok(())
}

fn load_kernel_config(path: &str) -> Result<HashMap<String, String>> {
    let content = fs::read_to_string(path)
        .map_err(|e| crate::error::OcfgError::Io(e))?;
    
    let mut config = HashMap::new();
    
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        
        if let Some((key, value)) = line.split_once('=') {
            config.insert(key.trim().to_string(), value.trim().to_string());
        }
    }
    
    Ok(config)
}

fn display_results(result: &DependencyCheckResult, show_recommended: bool) {
    println!("\n=== Dependency Check Results ===\n");

    if result.is_clean() {
        println!("✓ All dependencies satisfied!");
        return;
    }

    // Display missing required dependencies
    if !result.missing_required.is_empty() {
        println!("❌ Missing Required Dependencies:");
        for dep in &result.missing_required {
            println!("  - {} requires: {} (required)", dep.package, dep.missing);
        }
        println!();
    }

    // Display conflicts
    if !result.conflicts_found.is_empty() {
        println!("❌ Package Conflicts:");
        for conflict in &result.conflicts_found {
            println!("  - {} conflicts with {}", conflict.package1, conflict.package2);
        }
        println!();
    }

    // Display missing recommended dependencies
    if show_recommended && !result.missing_recommended.is_empty() {
        println!("⚠️  Missing Recommended Dependencies:");
        for dep in &result.missing_recommended {
            println!("  - {} recommends: {} (for full functionality)", dep.package, dep.missing);
        }
        println!();
    }

    // Display missing kernel options
    if !result.missing_kernel.is_empty() {
        println!("⚠️  Missing Kernel Options:");
        for kernel in &result.missing_kernel {
            let status = if kernel.required { "required" } else { "recommended" };
            println!("  - {} needs kernel option: {} ({})", kernel.package, kernel.option, status);
            println!("    Description: {}", kernel.description);
        }
        println!();
    }

    // Summary
    println!("=== Summary ===");
    println!("Missing required: {}", result.missing_required.len());
    if show_recommended {
        println!("Missing recommended: {}", result.missing_recommended.len());
    }
    println!("Missing kernel options: {}", result.missing_kernel.len());
    println!("Conflicts: {}", result.conflicts_found.len());
}

async fn fix_dependencies(
    config: &OcfgConfig,
    result: &DependencyCheckResult,
    knowledge_base: &DependencyKnowledgeBase,
) -> Result<()> {
    println!("\n=== Fixing Dependencies ===\n");

    let mut fixed_packages = Vec::new();
    
    // Add missing recommended dependencies
    for dep in &result.missing_recommended {
        println!("Adding recommended package: {}", dep.missing);
        fixed_packages.push(dep.missing.clone());
    }

    if !fixed_packages.is_empty() {
        println!("\nTo add these packages, run:");
        println!("ocfg config-packages --add {} --kernel", fixed_packages.join(" "));
    }

    // Show crypto library consistency warnings
    check_crypto_consistency(config, knowledge_base);

    Ok(())
}

fn check_crypto_consistency(config: &OcfgConfig, _knowledge_base: &DependencyKnowledgeBase) {
    println!("\n=== Crypto Library Consistency Check ===\n");
    
    let crypto_lib = &config.build.crypto_library;
    println!("Selected crypto library: {}", crypto_lib);

    let mut inconsistencies = Vec::new();

    // Check common packages that need crypto library consistency
    let crypto_packages = vec![
        ("openvpn", vec!["openvpn-openssl", "openvpn-mbedtls", "openvpn-wolfssl"]),
        ("hostapd", vec!["hostapd-openssl", "hostapd-mbedtls", "hostapd-wolfssl"]),
        ("wpad", vec!["wpad-openssl", "wpad-mbedtls", "wpad-wolfssl"]),
        ("wpa-supplicant", vec!["wpa-supplicant-openssl", "wpa-supplicant-mbedtls", "wpa-supplicant-wolfssl"]),
    ];

    for (base, variants) in crypto_packages {
        let expected = match crypto_lib {
            crate::config::CryptoLibrary::OpenSSL => format!("{}-openssl", base),
            crate::config::CryptoLibrary::MbedTLS => format!("{}-mbedtls", base),
            crate::config::CryptoLibrary::WolfSSL => format!("{}-wolfssl", base),
        };

        for variant in variants {
            if config.build.extra_packages.contains(&variant.to_string()) {
                if variant != &expected {
                    inconsistencies.push((variant, expected.clone()));
                }
            }
        }
    }

    if !inconsistencies.is_empty() {
        println!("⚠️  Crypto library inconsistencies found:");
        for (current, expected) in &inconsistencies {
            println!("  - {} should be {} for consistency", current, expected);
        }
        println!("\nRecommended actions:");
        for (current, expected) in &inconsistencies {
            println!("  - Remove: {}", current);
            println!("  - Add: {}", expected);
        }
    } else {
        println!("✓ All crypto packages are consistent");
    }
}
