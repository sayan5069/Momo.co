//! BORU Filesystem Rollback — Shadow backup and restore
//!
//! Before BORU allows any FILE_WRITE on an existing file,
//! it silently copies the original to .momo_shadow/<session_id>/.
//! On rollback, every modified file is restored.

use crate::cage::log_intercept;
use crate::cage::Severity;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// Shadow backup metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowManifest {
    /// Session ID
    pub session_id: String,
    /// When the shadow was created
    pub created: String,
    /// List of backed-up files
    pub files: Vec<ShadowFile>,
}

impl ShadowManifest {
    /// Create new manifest
    pub fn new(session_id: String) -> Self {
        Self {
            session_id,
            created: chrono::Utc::now().to_rfc3339(),
            files: Vec::new(),
        }
    }

    /// Add a file to the manifest
    pub fn add_file(&mut self, path_hash: String, original_path: PathBuf, size_bytes: u64) {
        self.files.push(ShadowFile {
            path_hash,
            original_path: original_path.to_string_lossy().to_string(),
            backed_up_at: chrono::Utc::now().to_rfc3339(),
            size_bytes,
        });
    }

    /// Save manifest to file
    pub fn save(&self, path: &Path) -> Result<()> {
        let content = serde_json::to_string_pretty(self)?;
        std::fs::write(path, content)
            .with_context(|| format!("Failed to write manifest: {}", path.display()))?;
        Ok(())
    }

    /// Load manifest from file
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read manifest: {}", path.display()))?;
        let manifest: ShadowManifest = serde_json::from_str(&content)
            .with_context(|| format!("Failed to parse manifest: {}", path.display()))?;
        Ok(manifest)
    }
}

/// Individual shadow file entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowFile {
    /// Hash of the path (used as filename)
    pub path_hash: String,
    /// Original file path
    pub original_path: String,
    /// When it was backed up
    pub backed_up_at: String,
    /// Size in bytes
    pub size_bytes: u64,
}

/// Rollback manager
pub struct RollbackManager {
    /// Shadow directory base path
    shadow_dir: PathBuf,
}

impl RollbackManager {
    /// Create new rollback manager with default shadow location
    pub fn new() -> Result<Self> {
        let shadow_dir = Self::default_shadow_dir()?;
        Ok(Self { shadow_dir })
    }

    /// Create new rollback manager with custom shadow location
    pub fn with_shadow_dir(shadow_dir: PathBuf) -> Self {
        Self { shadow_dir }
    }

    /// Get default shadow directory
    fn default_shadow_dir() -> Result<PathBuf> {
        let data_dir = dirs::data_dir()
            .or_else(|| dirs::home_dir().map(|h| h.join(".local/share")))
            .context("Could not find data directory")?;
        Ok(data_dir.join("boru").join("shadow"))
    }

    /// Get shadow directory for a session
    fn session_shadow_dir(&self, session_id: &str) -> PathBuf {
        self.shadow_dir.join(session_id)
    }

    /// Get shadow backup path for a file
    fn shadow_backup_path(&self, session_id: &str, path: &Path) -> PathBuf {
        let path_hash = compute_path_hash(path);
        self.session_shadow_dir(session_id).join(format!("{}.bak", path_hash))
    }

    /// Check if a file has already been backed up for this session
    pub fn is_backed_up(&self, session_id: &str, path: &Path) -> bool {
        self.shadow_backup_path(session_id, path).exists()
    }

    /// Create a shadow backup of a file
    ///
    /// Only backs up if:
    /// 1. File exists
    /// 2. File hasn't already been backed up for this session
    pub fn backup(&self, path: &Path, session_id: &str) -> Result<bool> {
        // Only back up existing files
        if !path.exists() {
            return Ok(false);
        }

        // Only back up once per file per session
        if self.is_backed_up(session_id, path) {
            return Ok(false);
        }

        let shadow_dir = self.session_shadow_dir(session_id);
        std::fs::create_dir_all(&shadow_dir)
            .with_context(|| format!("Failed to create shadow directory: {}", shadow_dir.display()))?;

        let backup_path = self.shadow_backup_path(session_id, path);

        // Copy file to shadow
        std::fs::copy(path, &backup_path)
            .with_context(|| format!("Failed to create shadow backup: {}", backup_path.display()))?;

        // Update manifest
        let manifest_path = shadow_dir.join("manifest.json");
        let mut manifest = if manifest_path.exists() {
            ShadowManifest::load(&manifest_path).unwrap_or_else(|_| ShadowManifest::new(session_id.to_string()))
        } else {
            ShadowManifest::new(session_id.to_string())
        };

        let metadata = std::fs::metadata(path)?;
        manifest.add_file(
            compute_path_hash(path),
            path.to_path_buf(),
            metadata.len(),
        );
        manifest.save(&manifest_path)?;

        // Log backup creation
        let request_id = uuid::Uuid::new_v4();
        log_intercept(
            Severity::Low,
            "SHADOW_BACKUP_CREATED",
            &format!("Backup: {} -> {}", path.display(), backup_path.display()),
            request_id,
        );

        Ok(true)
    }

    /// Restore a single file
    pub fn restore_file(&self, session_id: &str, original_path: &Path) -> Result<bool> {
        let backup_path = self.shadow_backup_path(session_id, original_path);

        if !backup_path.exists() {
            return Ok(false);
        }

        // Ensure parent directory exists
        if let Some(parent) = original_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Restore file
        std::fs::copy(&backup_path, original_path)
            .with_context(|| format!("Failed to restore: {} -> {}", backup_path.display(), original_path.display()))?;

        let request_id = uuid::Uuid::new_v4();
        log_intercept(
            Severity::Low,
            "SHADOW_RESTORE",
            &format!("Restored: {}", original_path.display()),
            request_id,
        );

        Ok(true)
    }

    /// Restore all files for a session
    pub fn rollback(&self, session_id: &str) -> Result<RollbackResult> {
        let shadow_dir = self.session_shadow_dir(session_id);
        let manifest_path = shadow_dir.join("manifest.json");

        if !manifest_path.exists() {
            anyhow::bail!("No shadow backup found for session: {}", session_id);
        }

        let manifest = ShadowManifest::load(&manifest_path)?;
        let mut restored = Vec::new();
        let mut failed = Vec::new();

        for file in &manifest.files {
            let original_path = PathBuf::from(&file.original_path);
            match self.restore_file(session_id, &original_path) {
                Ok(true) => restored.push(original_path),
                Ok(false) => failed.push((original_path, "Backup not found".to_string())),
                Err(e) => failed.push((original_path, e.to_string())),
            }
        }

        Ok(RollbackResult { restored, failed })
    }

    /// List all sessions with shadow backups
    pub fn list_sessions(&self) -> Result<Vec<ShadowSessionInfo>> {
        let mut sessions = Vec::new();

        if !self.shadow_dir.exists() {
            return Ok(sessions);
        }

        for entry in std::fs::read_dir(&self.shadow_dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_dir() {
                let session_id = path.file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("unknown")
                    .to_string();

                let manifest_path = path.join("manifest.json");
                if let Ok(manifest) = ShadowManifest::load(&manifest_path) {
                    sessions.push(ShadowSessionInfo {
                        session_id,
                        created: manifest.created,
                        file_count: manifest.files.len(),
                    });
                }
            }
        }

        // Sort by creation time (newest first)
        sessions.sort_by(|a, b| b.created.cmp(&a.created));

        Ok(sessions)
    }

    /// Clear shadow backup for a session
    pub fn clear(&self, session_id: &str) -> Result<()> {
        let shadow_dir = self.session_shadow_dir(session_id);

        if shadow_dir.exists() {
            std::fs::remove_dir_all(&shadow_dir)
                .with_context(|| format!("Failed to clear shadow: {}", shadow_dir.display()))?;
        }

        let request_id = uuid::Uuid::new_v4();
        log_intercept(
            Severity::Low,
            "SHADOW_CLEARED",
            &format!("Cleared shadow for session: {}", session_id),
            request_id,
        );

        Ok(())
    }

    /// Dry-run rollback (shows what would be restored)
    pub fn dry_run(&self, session_id: &str) -> Result<Vec<PathBuf>> {
        let shadow_dir = self.session_shadow_dir(session_id);
        let manifest_path = shadow_dir.join("manifest.json");

        if !manifest_path.exists() {
            anyhow::bail!("No shadow backup found for session: {}", session_id);
        }

        let manifest = ShadowManifest::load(&manifest_path)?;
        Ok(manifest.files.iter().map(|f| PathBuf::from(&f.original_path)).collect())
    }

    /// Check if shadow exists for session
    pub fn has_shadow(&self, session_id: &str) -> bool {
        self.session_shadow_dir(session_id).join("manifest.json").exists()
    }
}

impl Default for RollbackManager {
    fn default() -> Self {
        Self::new().expect("Failed to create default RollbackManager")
    }
}

/// Rollback operation result
#[derive(Debug, Clone)]
pub struct RollbackResult {
    /// Successfully restored files
    pub restored: Vec<PathBuf>,
    /// Failed restorations
    pub failed: Vec<(PathBuf, String)>,
}

impl RollbackResult {
    /// Check if rollback was successful
    pub fn is_success(&self) -> bool {
        self.failed.is_empty()
    }

    /// Get success count
    pub fn success_count(&self) -> usize {
        self.restored.len()
    }

    /// Get failure count
    pub fn failure_count(&self) -> usize {
        self.failed.len()
    }
}

/// Shadow session info for listing
#[derive(Debug, Clone)]
pub struct ShadowSessionInfo {
    pub session_id: String,
    pub created: String,
    pub file_count: usize,
}

/// Compute SHA-256 hash of a path
pub fn compute_path_hash(path: &Path) -> String {
    let path_str = path.to_string_lossy();
    format!("{:x}", Sha256::digest(path_str.as_bytes()))[..16].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_compute_path_hash() {
        let path = PathBuf::from("/home/user/test.txt");
        let hash1 = compute_path_hash(&path);
        let hash2 = compute_path_hash(&path);

        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 16);
    }

    #[test]
    fn test_shadow_manifest() {
        let mut manifest = ShadowManifest::new("test-session".to_string());
        manifest.add_file(
            "abc123".to_string(),
            PathBuf::from("/tmp/test.txt"),
            1024,
        );

        assert_eq!(manifest.files.len(), 1);
        assert_eq!(manifest.session_id, "test-session");
    }

    #[test]
    fn test_rollback_result() {
        let result = RollbackResult {
            restored: vec![PathBuf::from("/tmp/a.txt"), PathBuf::from("/tmp/b.txt")],
            failed: vec![],
        };

        assert!(result.is_success());
        assert_eq!(result.success_count(), 2);
        assert_eq!(result.failure_count(), 0);
    }
}
