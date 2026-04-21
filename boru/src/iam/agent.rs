//! BORU Agent IAM — Agent identity management
//!
//! Each coding agent (Claude, GPT, Copilot, etc.) gets a unique token.
//! Tokens are SHA-256 hashed — never stored in plaintext.
//! Permissions are scoped per agent.
//!
//! Token flow:
//!   1. `boru iam --create-agent <name>` → prints token ONCE
//!   2. Agent sends token with every socket request
//!   3. BORU hashes token, looks up agent record
//!   4. Checks permissions before proceeding

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

/// Default IAM database path
fn default_iam_path() -> PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("boru")
        .join("iam.json")
}

/// Agent permissions
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum AgentPermission {
    /// Can execute files in cage
    Execute,
    /// Can read files in workspace
    FileRead,
    /// Can write files in workspace
    FileWrite,
    /// Can scan directories
    Scan,
    /// Can view audit logs
    AuditRead,
    /// Can view session replays
    SessionRead,
    /// Can trigger rollback
    Rollback,
    /// Can manage other agents (admin)
    Admin,
}

impl std::fmt::Display for AgentPermission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AgentPermission::Execute => write!(f, "execute"),
            AgentPermission::FileRead => write!(f, "file_read"),
            AgentPermission::FileWrite => write!(f, "file_write"),
            AgentPermission::Scan => write!(f, "scan"),
            AgentPermission::AuditRead => write!(f, "audit_read"),
            AgentPermission::SessionRead => write!(f, "session_read"),
            AgentPermission::Rollback => write!(f, "rollback"),
            AgentPermission::Admin => write!(f, "admin"),
        }
    }
}

impl AgentPermission {
    /// Parse from string
    pub fn from_str_opt(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "execute" => Some(AgentPermission::Execute),
            "file_read" | "read" => Some(AgentPermission::FileRead),
            "file_write" | "write" => Some(AgentPermission::FileWrite),
            "scan" => Some(AgentPermission::Scan),
            "audit_read" | "audit" => Some(AgentPermission::AuditRead),
            "session_read" | "session" => Some(AgentPermission::SessionRead),
            "rollback" => Some(AgentPermission::Rollback),
            "admin" => Some(AgentPermission::Admin),
            _ => None,
        }
    }

    /// Default permissions for a new agent
    pub fn defaults() -> HashSet<Self> {
        let mut perms = HashSet::new();
        perms.insert(AgentPermission::Execute);
        perms.insert(AgentPermission::FileRead);
        perms.insert(AgentPermission::Scan);
        perms.insert(AgentPermission::AuditRead);
        perms.insert(AgentPermission::SessionRead);
        perms
    }

    /// All available permissions
    pub fn all() -> HashSet<Self> {
        let mut perms = HashSet::new();
        perms.insert(AgentPermission::Execute);
        perms.insert(AgentPermission::FileRead);
        perms.insert(AgentPermission::FileWrite);
        perms.insert(AgentPermission::Scan);
        perms.insert(AgentPermission::AuditRead);
        perms.insert(AgentPermission::SessionRead);
        perms.insert(AgentPermission::Rollback);
        perms.insert(AgentPermission::Admin);
        perms
    }
}

/// Agent token (contains only the hash — never the plaintext)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentToken {
    /// SHA-256 hash of the token (hex string)
    pub token_hash: String,
    /// When the token was created
    pub created: String,
    /// Whether the token is revoked
    pub revoked: bool,
}

/// Agent record in the IAM database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRecord {
    /// Agent name (e.g., "claude", "gpt4", "copilot")
    pub name: String,
    /// Agent description
    pub description: String,
    /// Token (hashed)
    pub token: AgentToken,
    /// Permissions
    pub permissions: HashSet<AgentPermission>,
    /// When the agent was registered
    pub registered: String,
    /// Last activity timestamp
    pub last_seen: Option<String>,
    /// Total requests made
    pub request_count: u64,
}

/// IAM database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IAMDatabase {
    /// Database version
    pub version: String,
    /// Last update
    pub updated: String,
    /// Agent records (keyed by token hash for O(1) lookup)
    pub agents: HashMap<String, AgentRecord>,
    /// Name-to-hash index for CLI lookups
    pub name_index: HashMap<String, String>,
}

impl IAMDatabase {
    /// Create empty database
    fn new() -> Self {
        Self {
            version: "1.0".to_string(),
            updated: chrono::Utc::now().to_rfc3339(),
            agents: HashMap::new(),
            name_index: HashMap::new(),
        }
    }

    /// Load from disk
    fn load() -> Result<Self> {
        let path = default_iam_path();

        if !path.exists() {
            return Ok(Self::new());
        }

        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("Failed to read IAM database: {}", path.display()))?;

        let db: IAMDatabase = serde_json::from_str(&content)
            .with_context(|| format!("Failed to parse IAM database: {}", path.display()))?;

        Ok(db)
    }

    /// Save to disk
    fn save(&self) -> Result<()> {
        let path = default_iam_path();

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let content = serde_json::to_string_pretty(self)
            .context("Failed to serialize IAM database")?;

        std::fs::write(&path, content)
            .with_context(|| format!("Failed to write IAM database: {}", path.display()))?;

        Ok(())
    }
}

/// Agent manager — handles registration, auth, and permission checks
pub struct AgentManager {
    db: IAMDatabase,
}

impl AgentManager {
    /// Initialize agent manager
    pub fn new() -> Result<Self> {
        let db = IAMDatabase::load()?;
        Ok(Self { db })
    }

    /// Create a new agent and return the plaintext token (shown ONCE)
    ///
    /// The token is generated, shown to the user, then only the SHA-256
    /// hash is stored. The plaintext is never persisted.
    pub fn create_agent(
        &mut self,
        name: &str,
        description: &str,
        permissions: Option<HashSet<AgentPermission>>,
    ) -> Result<String> {
        // Check for duplicate name
        if self.db.name_index.contains_key(name) {
            bail!("Agent '{}' already exists. Use --revoke first.", name);
        }

        // Generate token: boru_<uuid>
        let raw_token = format!("boru_{}", uuid::Uuid::new_v4());

        // Hash token — NEVER store plaintext
        let token_hash = hash_token(&raw_token);

        let perms = permissions.unwrap_or_else(AgentPermission::defaults);

        let record = AgentRecord {
            name: name.to_string(),
            description: description.to_string(),
            token: AgentToken {
                token_hash: token_hash.clone(),
                created: chrono::Utc::now().to_rfc3339(),
                revoked: false,
            },
            permissions: perms,
            registered: chrono::Utc::now().to_rfc3339(),
            last_seen: None,
            request_count: 0,
        };

        // Store by token hash
        self.db.agents.insert(token_hash.clone(), record);
        self.db.name_index.insert(name.to_string(), token_hash);
        self.db.updated = chrono::Utc::now().to_rfc3339();
        self.db.save()?;

        // Log agent creation — GATE 7
        let request_id = uuid::Uuid::new_v4();
        crate::cage::log_intercept(
            crate::cage::Severity::Medium,
            "IAM_AGENT_CREATED",
            &format!("Agent '{}' created", name),
            request_id,
        );

        // Return plaintext token — shown ONCE, then forgotten
        Ok(raw_token)
    }

    /// Authenticate an agent by plaintext token
    /// Returns the agent record if valid
    pub fn authenticate(&mut self, token: &str) -> Result<&AgentRecord> {
        let token_hash = hash_token(token);

        let agent = self.db.agents.get_mut(&token_hash);

        match agent {
            Some(agent) => {
                if agent.token.revoked {
                    // Log failed auth — GATE 7
                    let request_id = uuid::Uuid::new_v4();
                    crate::cage::log_intercept(
                        crate::cage::Severity::High,
                        "IAM_AUTH_REVOKED",
                        &format!("Revoked token used by agent '{}'", agent.name),
                        request_id,
                    );
                    bail!("Token has been revoked for agent '{}'", agent.name);
                }

                // Update last seen
                agent.last_seen = Some(chrono::Utc::now().to_rfc3339());
                agent.request_count += 1;

                // Save updated stats (ignore failures — not critical)
                let _ = self.db.save();

                // Return immutable reference
                Ok(self.db.agents.get(&token_hash).expect("just verified"))
            }
            None => {
                // Log failed auth — GATE 7
                let request_id = uuid::Uuid::new_v4();
                crate::cage::log_intercept(
                    crate::cage::Severity::High,
                    "IAM_AUTH_FAILED",
                    "Invalid token presented",
                    request_id,
                );
                bail!("Invalid agent token");
            }
        }
    }

    /// Check if an agent has a specific permission
    pub fn check_permission(&self, token: &str, permission: &AgentPermission) -> bool {
        let token_hash = hash_token(token);

        match self.db.agents.get(&token_hash) {
            Some(agent) => {
                !agent.token.revoked && agent.permissions.contains(permission)
            }
            None => false,
        }
    }

    /// Revoke an agent's token by name
    pub fn revoke_agent(&mut self, name: &str) -> Result<()> {
        let token_hash = self.db.name_index.get(name)
            .context(format!("Agent '{}' not found", name))?
            .clone();

        let agent = self.db.agents.get_mut(&token_hash)
            .context(format!("Agent record for '{}' not found", name))?;

        agent.token.revoked = true;
        self.db.updated = chrono::Utc::now().to_rfc3339();
        self.db.save()?;

        // Log revocation — GATE 7
        let request_id = uuid::Uuid::new_v4();
        crate::cage::log_intercept(
            crate::cage::Severity::High,
            "IAM_AGENT_REVOKED",
            &format!("Agent '{}' token revoked", name),
            request_id,
        );

        Ok(())
    }

    /// List all agents
    pub fn list_agents(&self) -> Vec<&AgentRecord> {
        self.db.agents.values().collect()
    }

    /// Get agent by name
    pub fn get_agent(&self, name: &str) -> Option<&AgentRecord> {
        let token_hash = self.db.name_index.get(name)?;
        self.db.agents.get(token_hash)
    }

    /// Show agent details
    pub fn show_agent(&self, name: &str) -> Result<String> {
        let agent = self.get_agent(name)
            .context(format!("Agent '{}' not found", name))?;

        let perms: Vec<String> = agent.permissions.iter()
            .map(|p| p.to_string())
            .collect();

        let status = if agent.token.revoked { "REVOKED" } else { "ACTIVE" };

        Ok(format!(
            "Agent: {}\nDescription: {}\nStatus: {}\nRegistered: {}\nLast Seen: {}\nRequests: {}\nPermissions: {}\nToken Hash: {}...",
            agent.name,
            agent.description,
            status,
            agent.registered,
            agent.last_seen.as_deref().unwrap_or("never"),
            agent.request_count,
            perms.join(", "),
            &agent.token.token_hash[..16],
        ))
    }

    /// Get agent count
    pub fn agent_count(&self) -> usize {
        self.db.agents.len()
    }
}

/// Hash a plaintext token using SHA-256
/// Tokens are NEVER stored in plaintext — only their hash
fn hash_token(token: &str) -> String {
    format!("{:x}", Sha256::digest(token.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_token() {
        let hash1 = hash_token("test_token");
        let hash2 = hash_token("test_token");
        let hash3 = hash_token("other_token");

        assert_eq!(hash1, hash2);
        assert_ne!(hash1, hash3);
        assert_eq!(hash1.len(), 64); // SHA-256 = 64 hex chars
    }

    #[test]
    fn test_agent_permission_defaults() {
        let defaults = AgentPermission::defaults();
        assert!(defaults.contains(&AgentPermission::Execute));
        assert!(defaults.contains(&AgentPermission::FileRead));
        assert!(defaults.contains(&AgentPermission::Scan));
        assert!(!defaults.contains(&AgentPermission::FileWrite)); // Write not in defaults
        assert!(!defaults.contains(&AgentPermission::Admin)); // Admin not in defaults
    }

    #[test]
    fn test_agent_permission_display() {
        assert_eq!(AgentPermission::Execute.to_string(), "execute");
        assert_eq!(AgentPermission::Admin.to_string(), "admin");
        assert_eq!(AgentPermission::FileRead.to_string(), "file_read");
    }

    #[test]
    fn test_agent_permission_parse() {
        assert_eq!(AgentPermission::from_str_opt("execute"), Some(AgentPermission::Execute));
        assert_eq!(AgentPermission::from_str_opt("admin"), Some(AgentPermission::Admin));
        assert_eq!(AgentPermission::from_str_opt("read"), Some(AgentPermission::FileRead));
        assert_eq!(AgentPermission::from_str_opt("invalid"), None);
    }

    #[test]
    fn test_iam_database_new() {
        let db = IAMDatabase::new();
        assert_eq!(db.version, "1.0");
        assert!(db.agents.is_empty());
        assert!(db.name_index.is_empty());
    }
}
