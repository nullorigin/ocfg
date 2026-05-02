use crate::dependencies::{DependencyInfo, DependencyCategory, KernelDependency};
use crate::error::Result;
use regex::Regex;

pub struct OpenWrtWikiParser {
    client: reqwest::Client,
}

impl OpenWrtWikiParser {
    pub fn new() -> Result<Self> {
        Ok(Self {
            client: reqwest::Client::new(),
        })
    }

    /// Fetch a package page from the OpenWrt wiki
    pub async fn fetch_package_page(&self, package: &str) -> Result<String> {
        let url = format!("https://openwrt.org/packages/pkg_{}", package);
        
        let response = self.client
            .get(&url)
            .send()
            .await
            .map_err(|e| crate::error::OcfgError::Config(format!("Failed to fetch wiki page: {}", e)))?;
        
        if !response.status().is_success() {
            return Err(crate::error::OcfgError::Config(format!("Wiki page not found for package: {}", package)));
        }
        
        let content = response
            .text()
            .await
            .map_err(|e| crate::error::OcfgError::Config(format!("Failed to read wiki content: {}", e)))?;
        
        Ok(content)
    }

    /// Parse a wiki page to extract dependency information
    pub fn parse_dependencies(&self, content: &str, package: &str) -> Result<DependencyInfo> {
        let mut required_deps = Vec::new();
        let mut recommended_deps = Vec::new();
        let optional_deps = Vec::new();
        let mut kernel_deps = Vec::new();
        let mut notes = Vec::new();

        // Parse dependencies section
        if let Some(deps_section) = self.extract_section(content, "Dependencies") {
            required_deps = self.parse_dependency_list(&deps_section);
        }

        // Parse recommended section
        if let Some(rec_section) = self.extract_section(content, "Recommended") {
            recommended_deps = self.parse_dependency_list(&rec_section);
        }

        // Parse kernel options
        if let Some(kernel_section) = self.extract_section(content, "Kernel") {
            kernel_deps = self.parse_kernel_options(&kernel_section);
        }

        // Parse notes/requirements
        if let Some(notes_section) = self.extract_section(content, "Notes") {
            notes = self.parse_notes(&notes_section);
        }

        Ok(DependencyInfo {
            package: package.to_string(),
            description: self.extract_description(content),
            category: self.infer_category(content, package),
            required_deps,
            recommended_deps,
            optional_deps,
            kernel_deps,
            conflicts: Vec::new(),
            notes,
        })
    }

    /// Extract a specific section from wiki content
    fn extract_section(&self, content: &str, section_name: &str) -> Option<String> {
        let escaped_name = regex::escape(section_name);
        let pattern = format!("={{3}}\\s*{}\\s*={{3}}", escaped_name);
        let re = Regex::new(&pattern).ok()?;
        
        if let Some(captures) = re.find(content) {
            let start = captures.end();
            
            // Find the next section header
            let next_section_re = Regex::new(r"\n={3,}\s*[A-Z]").ok()?;
            if let Some(next_match) = next_section_re.find(&content[start..]) {
                Some(content[start..start + next_match.start()].to_string())
            } else {
                Some(content[start..].to_string())
            }
        } else {
            None
        }
    }

    /// Parse a dependency list from section content
    fn parse_dependency_list(&self, content: &str) -> Vec<String> {
        let mut deps = Vec::new();
        
        // Look for bullet points or numbered lists with package names
        let lines: Vec<&str> = content.lines().collect();
        
        for line in lines {
            let line = line.trim();
            
            // Match patterns like "* package-name" or "- package-name" or "1. package-name"
            if line.starts_with('*') || line.starts_with('-') || line.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false) {
                // Extract package name (first word after the marker)
                let cleaned = line
                    .trim_start_matches('*')
                    .trim_start_matches('-')
                    .trim_start_matches(|c: char| c.is_ascii_digit())
                    .trim_start_matches('.')
                    .trim_start_matches(')')
                    .trim();
                
                if !cleaned.is_empty() {
                    // Take the first word as the package name
                    if let Some(package_name) = cleaned.split_whitespace().next() {
                        // Clean up any trailing punctuation
                        let package_name = package_name.trim_end_matches(|c: char| c == ',' || c == '.');
                        if !package_name.is_empty() && !package_name.starts_with("http") {
                            deps.push(package_name.to_string());
                        }
                    }
                }
            }
        }
        
        deps
    }

    /// Parse kernel options from section content
    fn parse_kernel_options(&self, content: &str) -> Vec<KernelDependency> {
        let mut kernel_deps = Vec::new();
        
        // Look for CONFIG_ options
        let config_re = Regex::new(r"CONFIG_[A-Z_0-9]+").unwrap();
        
        for line in content.lines() {
            if let Some(captures) = config_re.find(line) {
                let option = captures.as_str().to_string();
                
                // Try to determine if it's required or recommended
                let required = line.to_lowercase().contains("required") || line.to_lowercase().contains("must");
                let recommended = line.to_lowercase().contains("recommended") || line.to_lowercase().contains("should");
                
                kernel_deps.push(KernelDependency {
                    option: option.clone(),
                    description: self.extract_line_description(line),
                    required,
                    recommended: recommended || !required,
                });
            }
        }
        
        kernel_deps
    }

    /// Parse notes from section content
    fn parse_notes(&self, content: &str) -> Vec<String> {
        let mut notes = Vec::new();
        
        for line in content.lines() {
            let line = line.trim();
            if !line.is_empty() && (line.starts_with('*') || line.starts_with('-') || line.starts_with("•")) {
                let note = line
                    .trim_start_matches('*')
                    .trim_start_matches('-')
                    .trim_start_matches('•')
                    .trim();
                if !note.is_empty() {
                    notes.push(note.to_string());
                }
            }
        }
        
        notes
    }

    /// Extract package description from content
    fn extract_description(&self, content: &str) -> String {
        // Look for the first paragraph or description section
        let lines: Vec<&str> = content.lines().collect();
        
        for line in lines.iter().take(20) {
            let line = line.trim();
            if !line.is_empty() && !line.starts_with('=') && !line.starts_with('<') {
                return line.to_string();
            }
        }
        
        "No description available".to_string()
    }

    /// Infer category from package name and content
    fn infer_category(&self, content: &str, package: &str) -> DependencyCategory {
        let package_lower = package.to_lowercase();
        let _content_lower = content.to_lowercase();
        
        if package_lower.contains("vpn") || package_lower.contains("wireguard") || package_lower.contains("openvpn") {
            DependencyCategory::VPN
        } else if package_lower.contains("dns") || package_lower.contains("dnsmasq") || package_lower.contains("adblock") {
            DependencyCategory::DNS
        } else if package_lower.contains("firewall") || package_lower.contains("nftables") || package_lower.contains("iptables") {
            DependencyCategory::Security
        } else if package_lower.contains("wifi") || package_lower.contains("wireless") || package_lower.contains("hostapd") {
            DependencyCategory::Wireless
        } else if package_lower.contains("usb") || package_lower.contains("storage") || package_lower.contains("mount") {
            DependencyCategory::Storage
        } else if package_lower.contains("fs-") || package_lower.contains("ext4") || package_lower.contains("ntfs") {
            DependencyCategory::Filesystem
        } else if package_lower.contains("luci") || package_lower.contains("uhttpd") {
            DependencyCategory::Web
        } else if package_lower.contains("kmod-") {
            DependencyCategory::Kernel
        } else if package_lower.contains("radius") || package_lower.contains("auth") {
            DependencyCategory::Security
        } else {
            DependencyCategory::Utility
        }
    }

    /// Extract description from a single line
    fn extract_line_description(&self, line: &str) -> String {
        // Remove the CONFIG_ option and any leading punctuation
        let cleaned = line
            .trim_start_matches(|c: char| c == '*' || c == '-' || c.is_ascii_digit())
            .trim_start_matches('.')
            .trim_start_matches(')')
            .trim();
        
        // Remove the CONFIG_ option if present
        if let Some(pos) = cleaned.find(' ') {
            cleaned[pos..].trim().to_string()
        } else {
            cleaned.to_string()
        }
    }

    /// Search for packages matching a pattern
    pub async fn search_packages(&self, _pattern: &str) -> Result<Vec<String>> {
        // This would typically query the OpenWrt package index
        // For now, return a placeholder
        Ok(vec![
            "luci-app-adblock".to_string(),
            "luci-app-banip".to_string(),
            "wireguard-tools".to_string(),
            "openvpn-openssl".to_string(),
        ])
    }
}

impl Default for OpenWrtWikiParser {
    fn default() -> Self {
        Self::new().expect("Failed to create wiki parser")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_dependency_list() {
        let parser = OpenWrtWikiParser::new().unwrap();
        let content = "* libopenssl
- libmbedtls
1. libwolfssl
";
        let deps = parser.parse_dependency_list(content);
        assert_eq!(deps.len(), 3);
        assert!(deps.contains(&"libopenssl".to_string()));
    }

    #[test]
    fn test_infer_category() {
        let parser = OpenWrtWikiParser::new().unwrap();
        assert!(matches!(
            parser.infer_category("", "luci-app-adblock"),
            DependencyCategory::DNS
        ));
        assert!(matches!(
            parser.infer_category("", "wireguard-tools"),
            DependencyCategory::VPN
        ));
    }
}
