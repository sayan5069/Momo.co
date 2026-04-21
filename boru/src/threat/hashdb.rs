//! BORU Hash Database — Local malware hash detection
//!
//! Offline file of known malware hashes. SHA-256 hash lookup.
//! No cloud. No API. Fully offline security.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Default hash database file path
pub fn default_hashdb_path() -> PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("boru")
        .join("hashdb.json")
}

/// Severity level for hash entries
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Critical => write!(f, "CRITICAL"),
            Severity::High => write!(f, "HIGH"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::Low => write!(f, "LOW"),
        }
    }
}

/// Hash database entry
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HashEntry {
    /// Malware name
    pub name: String,
    /// Severity level
    pub severity: Severity,
    /// Malware family
    pub family: String,
    /// Date added (ISO-8601)
    pub added: String,
}

/// Hash status after checking
#[derive(Debug, Clone, PartialEq)]
pub enum HashStatus {
    /// File is clean (hash not in database)
    Clean,
    /// Known bad hash found
    KnownBad(HashEntry),
    /// Hash check failed or skipped
    Unknown,
}

impl std::fmt::Display for HashStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HashStatus::Clean => write!(f, "Clean"),
            HashStatus::KnownBad(entry) => write!(f, "KNOWN BAD: {} ({})", entry.name, entry.family),
            HashStatus::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Hash database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashDB {
    /// Database version
    pub version: String,
    /// Last update timestamp
    pub updated: String,
    /// Hash entries (key: SHA-256 hash)
    pub entries: HashMap<String, HashEntry>,
}

impl HashDB {
    /// Create a new empty hash database
    pub fn new() -> Self {
        Self {
            version: "1.0".to_string(),
            updated: chrono::Utc::now().to_rfc3339(),
            entries: HashMap::new(),
        }
    }

    /// Create hash database with default entries (EICAR test file)
    pub fn with_defaults() -> Self {
        let mut db = Self::new();
        db.add_defaults();
        db
    }

    /// Add default entries (EICAR test file)
    fn add_defaults(&mut self) {
        // EICAR test file hash — safe, industry-standard AV test
        // SHA256 of: X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
        self.entries.insert(
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f".to_string(),
            HashEntry {
                name: "EICAR-Test-File".to_string(),
                severity: Severity::Critical,
                family: "test".to_string(),
                added: "2024-01-15".to_string(),
            },
        );
    }

    /// Load hash database from file
    pub fn load() -> Result<Self> {
        let path = default_hashdb_path();

        if !path.exists() {
            // Create default database
            let db = Self::with_defaults();
            db.save()?;
            return Ok(db);
        }

        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("Failed to read hash database: {}", path.display()))?;

        let db: HashDB = serde_json::from_str(&content)
            .with_context(|| format!("Failed to parse hash database: {}", path.display()))?;

        Ok(db)
    }

    /// Load from specific path
    pub fn load_from(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read hash database: {}", path.display()))?;

        let db: HashDB = serde_json::from_str(&content)
            .with_context(|| format!("Failed to parse hash database: {}", path.display()))?;

        Ok(db)
    }

    /// Save hash database to file
    pub fn save(&self) -> Result<()> {
        let path = default_hashdb_path();

        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create directory: {}", parent.display()))?;
        }

        let content = serde_json::to_string_pretty(self)
            .context("Failed to serialize hash database")?;

        std::fs::write(&path, content)
            .with_context(|| format!("Failed to write hash database: {}", path.display()))?;

        Ok(())
    }

    /// Add a hash entry
    pub fn add(&mut self, hash: &str, entry: HashEntry) {
        let hash_normalized = hash.to_lowercase();
        self.entries.insert(hash_normalized, entry);
        self.updated = chrono::Utc::now().to_rfc3339();
    }

    /// Remove a hash entry
    pub fn remove(&mut self, hash: &str) -> bool {
        let hash_normalized = hash.to_lowercase();
        self.entries.remove(&hash_normalized).is_some()
    }

    /// Look up a hash
    pub fn lookup(&self, hash: &str) -> Option<&HashEntry> {
        let hash_normalized = hash.to_lowercase();
        self.entries.get(&hash_normalized)
    }

    /// Check a file's hash
    pub fn check_file(&self, path: &Path) -> Result<HashStatus> {
        let hash = compute_file_hash(path)?;

        match self.lookup(&hash) {
            Some(entry) => Ok(HashStatus::KnownBad(entry.clone())),
            None => Ok(HashStatus::Clean),
        }
    }

    /// Check a hash string directly
    pub fn check_hash(&self, hash: &str) -> HashStatus {
        match self.lookup(hash) {
            Some(entry) => HashStatus::KnownBad(entry.clone()),
            None => HashStatus::Clean,
        }
    }

    /// Get total number of entries
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if database is empty
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Get all entries as sorted vec
    pub fn entries_sorted(&self) -> Vec<(&String, &HashEntry)> {
        let mut entries: Vec<_> = self.entries.iter().collect();
        entries.sort_by(|a, b| a.0.cmp(b.0));
        entries
    }

    /// Get statistics
    pub fn stats(&self) -> HashDBStats {
        let total = self.entries.len();
        let critical = self.entries.values()
            .filter(|e| matches!(e.severity, Severity::Critical))
            .count();
        let high = self.entries.values()
            .filter(|e| matches!(e.severity, Severity::High))
            .count();
        let medium = self.entries.values()
            .filter(|e| matches!(e.severity, Severity::Medium))
            .count();
        let low = self.entries.values()
            .filter(|e| matches!(e.severity, Severity::Low))
            .count();

        HashDBStats {
            total,
            critical,
            high,
            medium,
            low,
            updated: self.updated.clone(),
        }
    }

    /// Import entries from another database
    pub fn import(&mut self, other: &HashDB) -> usize {
        let mut added = 0;
        for (hash, entry) in &other.entries {
            if !self.entries.contains_key(hash) {
                self.entries.insert(hash.clone(), entry.clone());
                added += 1;
            }
        }
        if added > 0 {
            self.updated = chrono::Utc::now().to_rfc3339();
        }
        added
    }

    /// Import from JSON file
    pub fn import_from_file(&mut self, path: &Path) -> Result<usize> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read import file: {}", path.display()))?;

        let other: HashDB = serde_json::from_str(&content)
            .with_context(|| format!("Failed to parse import file: {}", path.display()))?;

        let added = self.import(&other);
        Ok(added)
    }
}

impl Default for HashDB {
    fn default() -> Self {
        Self::new()
    }
}

/// Hash database statistics
#[derive(Debug, Clone)]
pub struct HashDBStats {
    pub total: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub updated: String,
}

impl std::fmt::Display for HashDBStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Total entries: {} | Critical: {} | High: {} | Medium: {} | Low: {} | Updated: {}",
            self.total, self.critical, self.high, self.medium, self.low, self.updated
        )
    }
}

/// Compute SHA-256 hash of a file
pub fn compute_file_hash(path: &Path) -> Result<String> {
    use std::io::Read;

    let file = std::fs::File::open(path)
        .with_context(|| format!("Failed to open file for hashing: {}", path.display()))?;

    let mut hasher = Sha256::new();
    let mut reader = std::io::BufReader::new(file);
    let mut buffer = [0u8; 8192];

    loop {
        let bytes_read = reader
            .read(&mut buffer)
            .with_context(|| format!("Failed to read file for hashing: {}", path.display()))?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    let hash = hasher.finalize();
    Ok(format!("{:x}", hash))
}

/// Compute SHA-256 hash of bytes
pub fn compute_bytes_hash(data: &[u8]) -> String {
    let hash = Sha256::digest(data);
    format!("{:x}", hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hashdb_new() {
        let db = HashDB::new();
        assert_eq!(db.version, "1.0");
        assert!(db.entries.is_empty());
    }

    #[test]
    fn test_hashdb_with_defaults() {
        let db = HashDB::with_defaults();
        assert!(!db.entries.is_empty());

        // Check EICAR hash is present
        let eicar_hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
        assert!(db.lookup(eicar_hash).is_some());
    }

    #[test]
    fn test_add_and_lookup() {
        let mut db = HashDB::new();

        db.add(
            "abc123",
            HashEntry {
                name: "TestMalware".to_string(),
                severity: Severity::Critical,
                family: "test".to_string(),
                added: "2024-01-15".to_string(),
            },
        );

        let entry = db.lookup("abc123").unwrap();
        assert_eq!(entry.name, "TestMalware");

        // Case insensitive
        let entry_upper = db.lookup("ABC123").unwrap();
        assert_eq!(entry_upper.name, "TestMalware");
    }

    #[test]
    fn test_remove() {
        let mut db = HashDB::new();
        db.add("abc123", HashEntry {
            name: "Test".to_string(),
            severity: Severity::Low,
            family: "test".to_string(),
            added: "2024-01-15".to_string(),
        });

        assert!(db.remove("abc123"));
        assert!(!db.remove("abc123"));
    }

    #[test]
    fn test_check_hash() {
        let mut db = HashDB::new();
        db.add("deadbeef", HashEntry {
            name: "BadHash".to_string(),
            severity: Severity::Critical,
            family: "malware".to_string(),
            added: "2024-01-15".to_string(),
        });

        let status = db.check_hash("deadbeef");
        assert!(matches!(status, HashStatus::KnownBad(_)));

        let status_clean = db.check_hash("cleanhash");
        assert_eq!(status_clean, HashStatus::Clean);
    }

    #[test]
    fn test_stats() {
        let mut db = HashDB::new();
        db.add("h1", HashEntry {
            name: "Crit".to_string(),
            severity: Severity::Critical,
            family: "test".to_string(),
            added: "2024-01-15".to_string(),
        });
        db.add("h2", HashEntry {
            name: "High".to_string(),
            severity: Severity::High,
            family: "test".to_string(),
            added: "2024-01-15".to_string(),
        });

        let stats = db.stats();
        assert_eq!(stats.total, 2);
        assert_eq!(stats.critical, 1);
        assert_eq!(stats.high, 1);
    }

    #[test]
    fn test_compute_bytes_hash() {
        let hash1 = compute_bytes_hash(b"hello");
        let hash2 = compute_bytes_hash(b"hello");
        let hash3 = compute_bytes_hash(b"world");

        assert_eq!(hash1, hash2);
        assert_ne!(hash1, hash3);

        // Verify against known SHA-256 of "hello"
        assert_eq!(
            hash1,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn test_hash_status_display() {
        let clean = HashStatus::Clean;
        assert_eq!(clean.to_string(), "Clean");

        let known = HashStatus::KnownBad(HashEntry {
            name: "Trojan".to_string(),
            severity: Severity::Critical,
            family: "win32".to_string(),
            added: "2024-01-15".to_string(),
        });
        assert!(known.to_string().contains("Trojan"));
    }
}
