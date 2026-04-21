//! BORU Configuration — User-saved custom rules
//!
//! Loads boru.custom.toml for CUSTOM mode preferences.
//! Format supports:
//! - "Always allow this path"
//! - "Always deny this type"

use crate::cage::policy::SecurityPolicy;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Configuration file path
pub const CONFIG_FILE_NAME: &str = "boru.custom.toml";

/// Custom configuration for BORU
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Config {
    /// Allowed paths (exact matches)
    #[serde(default)]
    pub allowed_paths: Vec<String>,

    /// Denied paths (exact matches)
    #[serde(default)]
    pub denied_paths: Vec<String>,

    /// Allowed file types (extensions without dot)
    #[serde(default)]
    pub allowed_types: Vec<String>,

    /// Denied file types (extensions without dot)
    #[serde(default)]
    pub denied_types: Vec<String>,

    /// Path-specific rules
    #[serde(default)]
    pub path_rules: Vec<PathRule>,
}

/// Path-specific rule
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PathRule {
    /// Path pattern (supports wildcards)
    pub pattern: String,
    /// Action: "allow" or "deny"
    pub action: String,
    /// Optional reason for rule
    pub reason: Option<String>,
}

impl Config {
    /// Create empty config
    pub fn new() -> Self {
        Self {
            allowed_paths: vec![],
            denied_paths: vec![],
            allowed_types: vec![],
            denied_types: vec![],
            path_rules: vec![],
        }
    }

    /// Load config from file
    pub fn load() -> Result<Self> {
        let config_path = Self::config_path()?;

        if !config_path.exists() {
            // Return default config
            return Ok(Self::new());
        }

        let content = std::fs::read_to_string(&config_path)
            .with_context(|| format!("Failed to read config: {}", config_path.display()))?;

        let config: Config = toml::from_str(&content)
            .with_context(|| format!("Failed to parse config: {}", config_path.display()))?;

        Ok(config)
    }

    /// Load config from specific path
    pub fn load_from(path: &std::path::Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config: {}", path.display()))?;

        let config: Config = toml::from_str(&content)
            .with_context(|| format!("Failed to parse config: {}", path.display()))?;

        Ok(config)
    }

    /// Save config to file
    pub fn save(&self) -> Result<()> {
        let config_path = Self::config_path()?;

        // Ensure parent directory exists
        if let Some(parent) = config_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let content = toml::to_string_pretty(self)?;
        std::fs::write(&config_path, content)
            .with_context(|| format!("Failed to write config: {}", config_path.display()))?;

        Ok(())
    }

    /// Get config file path
    pub fn config_path() -> Result<PathBuf> {
        let config_dir = dirs::config_dir()
            .or_else(|| dirs::home_dir().map(|h| h.join(".config")))
            .context("Could not find config directory")?;

        Ok(config_dir.join("boru").join(CONFIG_FILE_NAME))
    }

    /// Apply this config to a security policy
    pub fn apply_to_policy(&self, policy: &mut SecurityPolicy) {
        policy.allowed_paths = self.allowed_paths.iter().cloned().collect();
        policy.denied_paths = self.denied_paths.iter().cloned().collect();
        policy.allowed_types = self.allowed_types.iter().cloned().collect();
        policy.denied_types = self.denied_types.iter().cloned().collect();
    }

    /// Check if a path matches any rule
    pub fn check_path(&self, path: &str) -> Option<&PathRule> {
        self.path_rules.iter().find(|rule| {
            // Simple glob matching without regex
            if rule.pattern.contains('*') {
                let parts: Vec<&str> = rule.pattern.split('*').collect();
                if parts.len() == 2 {
                    let prefix = parts[0];
                    let suffix = parts[1];
                    if prefix.is_empty() {
                        path.ends_with(suffix)
                    } else if suffix.is_empty() {
                        path.starts_with(prefix)
                    } else {
                        path.starts_with(prefix) && path.ends_with(suffix)
                    }
                } else {
                    let pattern_parts: Vec<&str> = rule.pattern.split('*').filter(|p| !p.is_empty()).collect();
                    pattern_parts.iter().all(|p| path.contains(p))
                }
            } else {
                path == rule.pattern
            }
        })
    }

    /// Add an allowed path
    pub fn allow_path(&mut self, path: &str) {
        if !self.allowed_paths.contains(&path.to_string()) {
            self.allowed_paths.push(path.to_string());
        }
    }

    /// Add a denied path
    pub fn deny_path(&mut self, path: &str) {
        if !self.denied_paths.contains(&path.to_string()) {
            self.denied_paths.push(path.to_string());
        }
    }

    /// Add an allowed type
    pub fn allow_type(&mut self, ext: &str) {
        let ext_clean = ext.trim_start_matches('.').to_string();
        if !self.allowed_types.contains(&ext_clean) {
            self.allowed_types.push(ext_clean);
        }
    }

    /// Add a denied type
    pub fn deny_type(&mut self, ext: &str) {
        let ext_clean = ext.trim_start_matches('.').to_string();
        if !self.denied_types.contains(&ext_clean) {
            self.denied_types.push(ext_clean);
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::new()
    }
}

/// Example config file content
pub fn example_config() -> String {
    r#"# BORU Custom Configuration
# Place this file at ~/.config/boru/boru.custom.toml

# Paths that are always allowed (exact match or glob)
allowed_paths = [
    "/home/user/projects/safe",
    "/tmp/momo/workspace/*",
]

# Paths that are always denied
 denied_paths = [
    "/home/user/.ssh",
    "/etc/passwd",
]

# File types always allowed
allowed_types = ["txt", "md", "json"]

# File types always denied
# Windows: exe, dll, bat, cmd, scr, msi
# Linux: so, elf, bin, out, appimage, deb, rpm
# macOS: dylib, app, dmg
denied_types = [
    "exe", "dll", "bat", "cmd", "scr", "msi",
    "so", "elf", "bin", "out", "appimage", "deb", "rpm",
    "dylib", "app", "dmg",
]

# Path-specific rules with reasons
[[path_rules]]
pattern = "/home/user/downloads/*"
action = "prompt"
reason = "Downloaded files require review"

[[path_rules]]
pattern = "/tmp/momo/trusted/*"
action = "allow"
reason = "Trusted workspace"
"#
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_serialization() {
        let config = Config {
            allowed_paths: vec!["/tmp/safe".to_string()],
            denied_paths: vec!["/etc".to_string()],
            allowed_types: vec!["txt".to_string()],
            denied_types: vec!["exe".to_string()],
            path_rules: vec![PathRule {
                pattern: "*.txt".to_string(),
                action: "allow".to_string(),
                reason: Some("Text files are safe".to_string()),
            }],
        };

        let toml_str = toml::to_string(&config).unwrap();
        assert!(toml_str.contains("allowed_paths"));
        assert!(toml_str.contains("/tmp/safe"));
    }

    #[test]
    fn test_allow_deny_helpers() {
        let mut config = Config::new();

        config.allow_path("/tmp/safe");
        config.deny_path("/etc");
        config.allow_type("txt");
        config.deny_type("exe");

        assert!(config.allowed_paths.contains(&"/tmp/safe".to_string()));
        assert!(config.denied_paths.contains(&"/etc".to_string()));
        assert!(config.allowed_types.contains(&"txt".to_string()));
        assert!(config.denied_types.contains(&"exe".to_string()));
    }
}
