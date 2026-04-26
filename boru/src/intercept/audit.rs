//! BORU Audit Tamper Chain — Tamper-evident audit logging
//!
//! Each audit log entry hashes its own content + previous entry's hash.
//! Creating a tamper-evident chain. If anyone edits or deletes an entry,
//! the chain breaks.
//!
//! Format: boru log --verify checks the entire chain integrity.

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::PathBuf;

/// Genesis hash (all zeros)
pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Compute hash for an audit entry
///
/// entry_hash = SHA256(seq + timestamp + event + verdict + prev_hash)
pub fn compute_entry_hash(
    seq: u64,
    timestamp: &str,
    event_type: &str,
    verdict: &str,
    prev_hash: &str,
) -> String {
    let content = format!("{}|{}|{}|{}|{}", seq, timestamp.trim(), event_type.trim(), verdict.trim_end(), prev_hash.trim());
    format!("{:064x}", Sha256::digest(content.as_bytes()))
}

/// Audit entry with chain hash
#[derive(Debug, Clone)]
pub struct ChainedEntry {
    /// Sequence number
    pub seq: u64,
    /// Timestamp
    pub timestamp: String,
    /// Event type
    pub event_type: String,
    /// Severity
    pub severity: String,
    /// Verdict/action
    pub verdict: String,
    /// Hash of this entry
    pub entry_hash: String,
    /// Hash of previous entry
    pub prev_hash: String,
}

impl ChainedEntry {
    /// Compute the hash for this entry
    pub fn compute_hash(&self) -> String {
        compute_entry_hash(
            self.seq,
            &self.timestamp,
            &self.event_type,
            &self.verdict,
            &self.prev_hash,
        )
    }

    /// Verify the entry hash is correct
    pub fn verify(&self) -> bool {
        self.entry_hash == self.compute_hash()
    }

    /// Format as log line
    pub fn to_log_line(&self) -> String {
        format!(
            "[{}] [{}] [{}] [{}] [seq:{}] [hash:{}] [prev:{}]",
            self.timestamp,
            self.severity,
            self.event_type,
            self.verdict.replace("\n", "\\n"),
            self.seq,
            &self.entry_hash,
            &self.prev_hash
        )
    }
}

/// Tamper chain verifier
pub struct TamperChain {
    entries: Vec<ChainedEntry>,
}

impl TamperChain {
    /// Load chain from audit log file
    pub fn load() -> Result<Self> {
        let log_path = crate::cage::get_audit_log_path();

        if !log_path.exists() {
            return Ok(Self { entries: vec![] });
        }

        let content = std::fs::read_to_string(&log_path)
            .with_context(|| format!("Failed to read audit log: {}", log_path.display()))?;

        let mut entries = Vec::new();
        let mut seq = 1u64;

        for line in content.lines() {
            if line.trim().is_empty() {
                continue;
            }

            // Try to parse existing chained format first
            if let Some(entry) = Self::parse_chained_line(line) {
                entries.push(entry);
            } else {
                // Parse legacy format and add chain data
                if let Some((timestamp, severity, event, verdict)) = Self::parse_legacy_line(line) {
                    let prev_hash = if seq == 1 {
                        GENESIS_HASH.to_string()
                    } else {
                        entries.last().map(|e| e.entry_hash.clone()).unwrap_or_else(|| GENESIS_HASH.to_string())
                    };

                    let entry_hash = compute_entry_hash(seq, &timestamp, &event, &verdict, &prev_hash);

                    entries.push(ChainedEntry {
                        seq,
                        timestamp,
                        severity,
                        event_type: event,
                        verdict,
                        entry_hash,
                        prev_hash,
                    });
                }
            }

            seq += 1;
        }

        Ok(Self { entries })
    }

    /// Parse a legacy format line: [timestamp] [severity] [action] [reason]
    fn parse_legacy_line(line: &str) -> Option<(String, String, String, String)> {
        let parts: Vec<&str> = line.split("] ").collect();
        if parts.len() >= 4 {
            let timestamp = parts[0].trim_start_matches('[').to_string();
            let severity = parts[1].trim_start_matches('[').to_string();
            let event = parts[2].trim_start_matches('[').to_string();
            let verdict = parts[3..].join("] ").trim_matches(|c| c == '[' || c == ']').to_string();
            Some((timestamp, severity, event, verdict))
        } else {
            None
        }
    }

    /// Parse a chained format line
    fn parse_chained_line(line: &str) -> Option<ChainedEntry> {
        // Format: [timestamp] [severity] [event] [verdict] [seq:N] [hash:H] [prev:P]
        if !line.contains("[seq:") {
            return None;
        }

        let parts: Vec<&str> = line.split("] ").collect();
        if parts.len() < 7 {
            return None;
        }

        let timestamp = parts[0].trim_start_matches('[').to_string();
        let severity = parts[1].trim_start_matches('[').to_string();
        let event_type = parts[2].trim_start_matches('[').to_string();
        let verdict = parts[3].trim_start_matches('[').replace("\\n", "\n");

        let seq_part = parts[4];
        let seq = seq_part
            .trim_start_matches("[seq:")
            .trim_end_matches(']')
            .parse::<u64>()
            .ok()?;

        let hash_part = parts[5];
        let entry_hash = hash_part
            .trim_start_matches("[hash:")
            .trim_end_matches(']')
            .to_string();

        let prev_part = parts[6];
        let prev_hash = prev_part
            .trim_start_matches("[prev:")
            .trim_end_matches(']')
            .to_string();

        Some(ChainedEntry {
            seq,
            timestamp,
            severity,
            event_type,
            verdict,
            entry_hash,
            prev_hash,
        })
    }

    /// Verify the entire chain
    pub fn verify(&self) -> ChainVerification {
        if self.entries.is_empty() {
            return ChainVerification::Empty;
        }

        // Verify genesis link
        if self.entries[0].prev_hash != GENESIS_HASH {
            return ChainVerification::Broken {
                at_entry: 1,
                expected_prev: GENESIS_HASH.to_string(),
                found_prev: self.entries[0].prev_hash.clone(),
            };
        }

        for i in 0..self.entries.len() {
            // Verify entry's own hash (deterministic check)
            if !self.entries[i].verify() {
                return ChainVerification::Invalid {
                    entry: i + 1,
                    expected: self.entries[i].compute_hash(),
                    found: self.entries[i].entry_hash.clone(),
                };
            }

            if i > 0 {
                // Verify chain link
                let expected_hash = compute_entry_hash(
                    self.entries[i - 1].seq,
                    &self.entries[i - 1].timestamp,
                    &self.entries[i - 1].event_type,
                    &self.entries[i - 1].verdict,
                    &self.entries[i - 1].prev_hash,
                );

                if self.entries[i].prev_hash != expected_hash {
                    return ChainVerification::Broken {
                        at_entry: i + 1,
                        expected_prev: expected_hash,
                        found_prev: self.entries[i].prev_hash.clone(),
                    };
                }

                // Check for sequence gaps
                let expected_seq = self.entries[i - 1].seq + 1;
                if self.entries[i].seq != expected_seq {
                    return ChainVerification::Gap { at_entry: i + 1 };
                }
            }
        }

        ChainVerification::Valid {
            entries: self.entries.len(),
        }
    }

    /// Verify a single entry
    pub fn verify_entry(&self, seq: u64) -> Option<ChainVerification> {
        let entry = self.entries.iter().find(|e| e.seq == seq)?;

        if !entry.verify() {
            Some(ChainVerification::Invalid {
                entry: seq as usize,
                expected: entry.compute_hash(),
                found: entry.entry_hash.clone(),
            })
        } else {
            Some(ChainVerification::SingleValid { seq })
        }
    }

    /// Get number of entries
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Get all entries
    pub fn entries(&self) -> &[ChainedEntry] {
        &self.entries
    }

    /// Get next sequence number
    pub fn next_seq(&self) -> u64 {
        self.entries.last().map(|e| e.seq + 1).unwrap_or(1)
    }

    /// Get previous hash for next entry
    pub fn prev_hash(&self) -> String {
        self.entries.last().map(|e| e.entry_hash.clone()).unwrap_or_else(|| GENESIS_HASH.to_string())
    }
}

/// Chain verification result
#[derive(Debug, Clone)]
pub enum ChainVerification {
    /// Chain is valid and intact
    Valid { entries: usize },
    /// Single entry verified
    SingleValid { seq: u64 },
    /// Chain is broken (tampered)
    Broken {
        at_entry: usize,
        expected_prev: String,
        found_prev: String,
    },
    /// Chain has gaps (entries deleted)
    Gap { at_entry: usize },
    /// Entry hash doesn't match content
    Invalid {
        entry: usize,
        expected: String,
        found: String,
    },
    /// No entries to verify
    Empty,
}

impl ChainVerification {
    /// Check if valid
    pub fn is_valid(&self) -> bool {
        matches!(self, ChainVerification::Valid { .. } | ChainVerification::SingleValid { .. })
    }

    /// Get display message
    pub fn message(&self) -> String {
        match self {
            ChainVerification::Valid { entries } => {
                format!("✅ Chain intact — {} entries, no tampering detected", entries)
            }
            ChainVerification::SingleValid { seq } => {
                format!("✅ Entry #{} verified", seq)
            }
            ChainVerification::Broken {
                at_entry,
                expected_prev,
                found_prev,
            } => {
                format!(
                    "❌ Chain broken at entry #{}\n   Expected previous hash: {}...\n   Found previous hash: {}...",
                    at_entry,
                    &expected_prev[..16.min(expected_prev.len())],
                    &found_prev[..16.min(found_prev.len())]
                )
            }
            ChainVerification::Gap { at_entry } => {
                format!("❌ Chain gap at entry #{} — entry was deleted", at_entry)
            }
            ChainVerification::Invalid { entry, expected, found } => {
                format!(
                    "❌ Entry #{} modified\n   Expected hash: {}...\n   Found hash: {}...",
                    entry,
                    &expected[..16.min(expected.len())],
                    &found[..16.min(found.len())]
                )
            }
            ChainVerification::Empty => "⚠️ No entries to verify".to_string(),
        }
    }
}

/// Append a chained entry to the audit log
pub fn append_chained_entry(
    timestamp: &str,
    severity: &str,
    event_type: &str,
    verdict: &str,
) -> Result<()> {
    let chain = TamperChain::load()?;
    let seq = chain.next_seq();
    let prev_hash = chain.prev_hash();

    let entry_hash = compute_entry_hash(seq, timestamp, event_type, verdict, &prev_hash);

    let entry = ChainedEntry {
        seq,
        timestamp: timestamp.to_string(),
        severity: severity.to_string(),
        event_type: event_type.to_string(),
        verdict: verdict.to_string(),
        entry_hash,
        prev_hash,
    };

    let log_path = crate::cage::get_audit_log_path();

    // Ensure directory exists
    if let Some(parent) = log_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .with_context(|| format!("Failed to open audit log: {}", log_path.display()))?;

    writeln!(file, "{}", entry.to_log_line())
        .with_context(|| "Failed to write audit log entry")?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_entry_hash() {
        let hash1 = compute_entry_hash(1, "2024-01-01", "TEST", "ALLOWED", GENESIS_HASH);
        let hash2 = compute_entry_hash(1, "2024-01-01", "TEST", "ALLOWED", GENESIS_HASH);
        let hash3 = compute_entry_hash(2, "2024-01-01", "TEST", "ALLOWED", GENESIS_HASH);

        assert_eq!(hash1, hash2);
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_chained_entry_verify() {
        let entry = ChainedEntry {
            seq: 1,
            timestamp: "2024-01-01".to_string(),
            severity: "Low".to_string(),
            event_type: "TEST".to_string(),
            verdict: "ALLOWED".to_string(),
            entry_hash: compute_entry_hash(1, "2024-01-01", "TEST", "ALLOWED", GENESIS_HASH),
            prev_hash: GENESIS_HASH.to_string(),
        };

        assert!(entry.verify());

        // Tampered entry
        let mut tampered = entry.clone();
        tampered.verdict = "BLOCKED".to_string();
        assert!(!tampered.verify());
    }

    #[test]
    fn test_parse_legacy_line() {
        let line = "[2024-01-01T00:00:00Z] [Low] [TEST_ACTION] [Test reason]";
        let result = TamperChain::parse_legacy_line(line);
        assert!(result.is_some());

        let (ts, sev, event, verdict) = result.unwrap();
        assert_eq!(ts, "2024-01-01T00:00:00Z");
        assert_eq!(sev, "Low");
        assert_eq!(event, "TEST_ACTION");
        assert_eq!(verdict, "Test reason");
    }

    #[test]
    fn test_chain_verification_valid() {
        let entries = vec![
            ChainedEntry {
                seq: 1,
                timestamp: "2024-01-01".to_string(),
                severity: "Low".to_string(),
                event_type: "TEST".to_string(),
                verdict: "ALLOWED".to_string(),
                entry_hash: compute_entry_hash(1, "2024-01-01", "TEST", "ALLOWED", GENESIS_HASH),
                prev_hash: GENESIS_HASH.to_string(),
            },
            ChainedEntry {
                seq: 2,
                timestamp: "2024-01-01".to_string(),
                severity: "High".to_string(),
                event_type: "TEST2".to_string(),
                verdict: "BLOCKED".to_string(),
                entry_hash: compute_entry_hash(2, "2024-01-01", "TEST2", "BLOCKED", &compute_entry_hash(1, "2024-01-01", "TEST", "ALLOWED", GENESIS_HASH)),
                prev_hash: compute_entry_hash(1, "2024-01-01", "TEST", "ALLOWED", GENESIS_HASH),
            },
        ];

        let chain = TamperChain { entries };
        let result = chain.verify();

        assert!(result.is_valid());
        assert!(matches!(result, ChainVerification::Valid { entries: 2 }));
    }

    #[test]
    fn test_chain_verification_broken() {
        let entries = vec![
            ChainedEntry {
                seq: 1,
                timestamp: "2024-01-01".to_string(),
                severity: "Low".to_string(),
                event_type: "TEST".to_string(),
                verdict: "ALLOWED".to_string(),
                entry_hash: compute_entry_hash(1, "2024-01-01", "TEST", "ALLOWED", GENESIS_HASH),
                prev_hash: GENESIS_HASH.to_string(),
            },
            ChainedEntry {
                seq: 2,
                timestamp: "2024-01-01".to_string(),
                severity: "High".to_string(),
                event_type: "TEST2".to_string(),
                verdict: "BLOCKED".to_string(),
                entry_hash: compute_entry_hash(2, "2024-01-01", "TEST2", "BLOCKED", GENESIS_HASH), // Wrong prev_hash
                prev_hash: GENESIS_HASH.to_string(), // Should be hash of entry 1
            },
        ];

        let chain = TamperChain { entries };
        let result = chain.verify();

        assert!(!result.is_valid());
        assert!(matches!(result, ChainVerification::Broken { .. }));
    }

    #[test]
    fn test_chain_verification_empty() {
        let chain = TamperChain { entries: vec![] };
        let result = chain.verify();
        assert!(matches!(result, ChainVerification::Empty));
    }

    #[test]
    fn test_verification_messages() {
        let valid = ChainVerification::Valid { entries: 10 };
        assert!(valid.message().contains("intact"));

        let broken = ChainVerification::Broken {
            at_entry: 5,
            expected_prev: "abc123".to_string(),
            found_prev: "def456".to_string(),
        };
        assert!(broken.message().contains("broken"));

        let gap = ChainVerification::Gap { at_entry: 3 };
        assert!(gap.message().contains("gap"));
    }

    #[test]
    fn test_regression_tamper_chain() {
        let e1_hash = compute_entry_hash(1, "2024-01-01", "TEST1", "ALLOW", GENESIS_HASH);
        let e1 = ChainedEntry {
            seq: 1, timestamp: "2024-01-01".to_string(), severity: "Low".to_string(),
            event_type: "TEST1".to_string(), verdict: "ALLOW".to_string(),
            entry_hash: e1_hash.clone(), prev_hash: GENESIS_HASH.to_string(),
        };

        let e2_hash = compute_entry_hash(2, "2024-01-02", "TEST2", "BLOCK", &e1_hash);
        let mut e2 = ChainedEntry {
            seq: 2, timestamp: "2024-01-02".to_string(), severity: "High".to_string(),
            event_type: "TEST2".to_string(), verdict: "BLOCK".to_string(),
            entry_hash: e2_hash.clone(), prev_hash: e1_hash.clone(),
        };

        let e3_hash = compute_entry_hash(3, "2024-01-03", "TEST3", "ALLOW", &e2_hash);
        let e3 = ChainedEntry {
            seq: 3, timestamp: "2024-01-03".to_string(), severity: "Low".to_string(),
            event_type: "TEST3".to_string(), verdict: "ALLOW".to_string(),
            entry_hash: e3_hash.clone(), prev_hash: e2_hash.clone(),
        };

        let mut chain = TamperChain { entries: vec![e1.clone(), e2.clone(), e3.clone()] };
        assert!(chain.verify().is_valid());

        // Tamper with entry 2 content
        chain.entries[1].verdict = "ALLOW".to_string(); // tampered
        let res = chain.verify();
        assert!(matches!(res, ChainVerification::Invalid { entry: 2, .. }));

        // What if someone updates e2's entry hash to match the tampered content?
        let tampered_e2_hash = compute_entry_hash(2, "2024-01-02", "TEST2", "ALLOW", &e1_hash);
        chain.entries[1].entry_hash = tampered_e2_hash.clone();
        
        // Then it should break at entry 3 because e3's prev_hash won't match!
        let res2 = chain.verify();
        assert!(matches!(res2, ChainVerification::Broken { at_entry: 3, .. }));
    }
}
