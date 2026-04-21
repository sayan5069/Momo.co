//! BORU Quarantine — File isolation and metadata tracking
//!
//! When a file is DENIED (auto or by user):
//! 1. Move original to: /tmp/momo/quarantine/<timestamp>-<filename>/
//! 2. Write metadata.json alongside
//! 3. Log to audit log with quarantine_ref

use crate::cage;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Quarantine directory
const QUARANTINE_DIR: &str = "/tmp/momo/quarantine";

/// Quarantine metadata
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct QuarantineMetadata {
    /// ISO-8601 timestamp
    pub timestamp: String,
    /// Original file path
    pub original_path: String,
    /// Event type
    pub event_type: String,
    /// Severity level
    pub severity: String,
    /// Source session ID
    pub source_session: String,
    /// Reason for quarantine
    pub reason: String,
    /// Security mode at intercept
    pub mode_at_intercept: String,
    /// Final verdict
    pub verdict: String,
}

/// Quarantine a file
///
/// Returns the path to the quarantined file location
pub fn quarantine_file(
    original_path: &Path,
    event_type: &str,
    severity: cage::Severity,
    source_session: &str,
    reason: &str,
    mode_at_intercept: &str,
    verdict: &str,
) -> Result<PathBuf> {
    // Create quarantine directory
    let quarantine_base = PathBuf::from(QUARANTINE_DIR);
    std::fs::create_dir_all(&quarantine_base)
        .with_context(|| format!("Failed to create quarantine dir: {}", quarantine_base.display()))?;

    // Generate quarantine folder name
    let timestamp = chrono::Utc::now();
    let filename = original_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown");
    let quarantine_name = format!(
        "{}_{}",
        timestamp.format("%Y%m%dT%H%M%S"),
        sanitize_filename(filename)
    );
    let quarantine_folder = quarantine_base.join(&quarantine_name);

    // Create quarantine folder
    std::fs::create_dir_all(&quarantine_folder)
        .with_context(|| format!("Failed to create quarantine folder: {}", quarantine_folder.display()))?;

    // Determine quarantined filename
    let quarantined_filename = if original_path.extension().is_some() {
        "file.quarantined".to_string()
    } else {
        "file.quarantined".to_string()
    };

    let quarantine_path = quarantine_folder.join(&quarantined_filename);

    // Move file to quarantine
    std::fs::rename(original_path, &quarantine_path)
        .or_else(|_| {
            // If rename fails (cross-device), copy and delete
            std::fs::copy(original_path, &quarantine_path)?;
            let _ = std::fs::remove_file(original_path);
            Ok::<(), std::io::Error>(())
        })
        .with_context(|| {
            format!(
                "Failed to quarantine file from {} to {}",
                original_path.display(),
                quarantine_path.display()
            )
        })?;

    // Create metadata
    let metadata = QuarantineMetadata {
        timestamp: timestamp.to_rfc3339(),
        original_path: original_path.to_string_lossy().to_string(),
        event_type: event_type.to_string(),
        severity: format!("{:?}", severity),
        source_session: source_session.to_string(),
        reason: reason.to_string(),
        mode_at_intercept: mode_at_intercept.to_string(),
        verdict: verdict.to_string(),
    };

    // Write metadata.json
    let metadata_path = quarantine_folder.join("metadata.json");
    let metadata_json = serde_json::to_string_pretty(&metadata)?;
    std::fs::write(&metadata_path, metadata_json)
        .with_context(|| format!("Failed to write metadata: {}", metadata_path.display()))?;

    // Log to audit log
    let request_id = uuid::Uuid::new_v4();
    cage::log_intercept(
        severity,
        "QUARANTINE",
        &format!(
            "File quarantined: {} -> {} (reason: {})",
            original_path.display(),
            quarantine_folder.display(),
            reason
        ),
        request_id,
    );

    Ok(quarantine_folder)
}

/// Get all quarantined items
pub fn list_quarantined() -> Result<Vec<QuarantineItem>> {
    let quarantine_base = PathBuf::from(QUARANTINE_DIR);

    if !quarantine_base.exists() {
        return Ok(vec![]);
    }

    let mut items = vec![];

    for entry in std::fs::read_dir(&quarantine_base)? {
        let entry = entry?;
        let path = entry.path();

        if path.is_dir() {
            let metadata_path = path.join("metadata.json");
            if let Ok(content) = std::fs::read_to_string(&metadata_path) {
                if let Ok(metadata) = serde_json::from_str::<QuarantineMetadata>(&content
                ) {
                    items.push(QuarantineItem {
                        folder: path,
                        metadata,
                    });
                }
            }
        }
    }

    // Sort by timestamp (newest first)
    items.sort_by(|a, b| {
        b.metadata.timestamp.cmp(&a.metadata.timestamp)
    });

    Ok(items)
}

/// Restore a quarantined file to its original location
pub fn restore_quarantine(
    quarantine_folder: &Path
) -> Result<PathBuf> {
    let metadata_path = quarantine_folder.join("metadata.json");
    let metadata: QuarantineMetadata = serde_json::from_str(
        &std::fs::read_to_string(&metadata_path)?
    )?;

    let original_path = PathBuf::from(&metadata.original_path);
    let quarantined_file = quarantine_folder.join("file.quarantined");

    // Move file back
    std::fs::rename(&quarantined_file, &original_path)?;

    // Remove quarantine folder
    let _ = std::fs::remove_dir_all(quarantine_folder);

    // Log restoration
    let request_id = uuid::Uuid::new_v4();
    cage::log_intercept(
        cage::Severity::Low,
        "QUARANTINE_RESTORE",
        &format!("File restored: {}", original_path.display()),
        request_id,
    );

    Ok(original_path)
}

/// Delete a quarantined item permanently
pub fn delete_quarantine(
    quarantine_folder: &Path
) -> Result<()> {
    let metadata_path = quarantine_folder.join("metadata.json");
    let metadata: QuarantineMetadata = serde_json::from_str(
        &std::fs::read_to_string(&metadata_path)?
    )?;

    // Remove quarantine folder
    std::fs::remove_dir_all(quarantine_folder)?;

    // Log deletion
    let request_id = uuid::Uuid::new_v4();
    cage::log_intercept(
        cage::Severity::Low,
        "QUARANTINE_DELETE",
        &format!(
            "Quarantined file deleted: {}",
            metadata.original_path
        ),
        request_id,
    );

    Ok(())
}

/// Sanitize filename for quarantine storage
fn sanitize_filename(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '.' || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Quarantine item with metadata
#[derive(Debug, Clone)]
pub struct QuarantineItem {
    /// Path to quarantine folder
    pub folder: PathBuf,
    /// Quarantine metadata
    pub metadata: QuarantineMetadata,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_filename() {
        assert_eq!(sanitize_filename("test.txt"), "test.txt");
        assert_eq!(sanitize_filename("file with spaces.txt"), "file_with_spaces.txt");
        assert_eq!(sanitize_filename("path/to/file.txt"), "path_to_file.txt");
        assert_eq!(sanitize_filename("file\nwith\nnewlines"), "file_with_newlines");
    }
}
