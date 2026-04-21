//! BORU Directory Scanner — Recursive file analysis
//!
//! Scans directories recursively, classifying every file.
//! Runs entropy check + hash check on each.
//! Generates reports. No execution — pure analysis.

use crate::classifier::{FileClassifier, ClassificationResult};
use crate::cage::policy::SecurityMode;
use crate::scanner::entropy::{scan_file, EntropyResult, EntropyVerdict};
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

/// Final verdict for a scanned file
#[derive(Debug, Clone, PartialEq)]
pub enum Verdict {
    /// File is clean
    Clean,
    /// File is suspicious but allowed
    Suspicious,
    /// File is critical and should be blocked
    Critical,
    /// File is known bad (hash match)
    KnownBad,
}

impl std::fmt::Display for Verdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Verdict::Clean => write!(f, "CLEAN"),
            Verdict::Suspicious => write!(f, "SUSPICIOUS"),
            Verdict::Critical => write!(f, "CRITICAL"),
            Verdict::KnownBad => write!(f, "KNOWN BAD"),
        }
    }
}

/// Hash status from threat database (local wrapper)
#[derive(Debug, Clone, PartialEq)]
pub enum HashCheckResult {
    /// File hash not in database
    Clean,
    /// Known bad hash found
    KnownBad { name: String, family: String },
    /// Hash check skipped or unavailable
    Unknown,
}

impl std::fmt::Display for HashCheckResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HashCheckResult::Clean => write!(f, "Clean"),
            HashCheckResult::KnownBad { name, family } => {
                write!(f, "KNOWN BAD: {} (family: {})", name, family)
            }
            HashCheckResult::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Individual file scan result
#[derive(Debug, Clone)]
pub struct ScanResult {
    /// Path to file
    pub path: PathBuf,
    /// File classification
    pub file_class: crate::classifier::magic::FileClass,
    /// Entropy scan result
    pub entropy: EntropyResult,
    /// Hash database status
    pub hash_status: HashCheckResult,
    /// Final verdict
    pub verdict: Verdict,
    /// Reason for verdict
    pub reason: Option<String>,
}

impl ScanResult {
    /// Create display emoji for verdict
    pub fn emoji(&self) -> &'static str {
        match self.verdict {
            Verdict::Clean => "✅",
            Verdict::Suspicious => "⚠️",
            Verdict::Critical => "🚫",
            Verdict::KnownBad => "🔴",
        }
    }

    /// Get classification description
    pub fn class_description(&self) -> String {
        crate::classifier::magic::class_description(&self.file_class).to_string()
    }
}

/// Complete scan report
#[derive(Debug, Clone)]
pub struct ScanReport {
    /// Path that was scanned
    pub scan_path: PathBuf,
    /// Security mode used
    pub mode: SecurityMode,
    /// All scan results
    pub results: Vec<ScanResult>,
    /// Timestamp
    pub timestamp: String,
}

impl ScanReport {
    /// Create a new scan report
    pub fn new(scan_path: PathBuf, mode: SecurityMode) -> Self {
        Self {
            scan_path,
            mode,
            results: Vec::new(),
            timestamp: chrono::Utc::now().to_rfc3339(),
        }
    }

    /// Add a result
    pub fn add_result(&mut self, result: ScanResult) {
        self.results.push(result);
    }

    /// Get summary counts
    pub fn summary(&self) -> (usize, usize, usize, usize) {
        let clean = self.results.iter().filter(|r| r.verdict == Verdict::Clean).count();
        let suspicious = self.results.iter().filter(|r| r.verdict == Verdict::Suspicious).count();
        let critical = self.results.iter().filter(|r| r.verdict == Verdict::Critical).count();
        let known_bad = self.results.iter().filter(|r| r.verdict == Verdict::KnownBad).count();
        (clean, suspicious, critical, known_bad)
    }

    /// Generate markdown report
    pub fn to_markdown(&self) -> String {
        let (clean, suspicious, critical, known_bad) = self.summary();
        let total = self.results.len();

        let mut output = format!(
            "# BORU Scan Report\n\nGenerated: {}\nPath: {}\nMode: {:?}\n\n## Summary\n\n- Total files: {}\n- Clean: {}\n- Suspicious: {}\n- Critical: {}\n- Known bad: {}\n\n## Findings\n\n| File | Type | Entropy | Status | Reason |\n|------|------|---------|--------|--------|\n",
            self.timestamp,
            self.scan_path.display(),
            self.mode,
            total,
            clean,
            suspicious,
            critical,
            known_bad
        );

        for result in &self.results {
            let entropy_str = format!("{:.2}", result.entropy.score);
            let reason = result.reason.as_deref().unwrap_or("-");
            output.push_str(&format!(
                "| {} | {} | {} | {} | {} |\n",
                result.path.display(),
                result.class_description(),
                entropy_str,
                result.verdict,
                reason
            ));
        }

        let quarantined: Vec<_> = self.results.iter()
            .filter(|r| matches!(r.verdict, Verdict::Critical | Verdict::KnownBad))
            .collect();

        if !quarantined.is_empty() {
            output.push_str("\n## Quarantined Files\n\n");
            for result in quarantined {
                output.push_str(&format!("- {}: {}\n", result.path.display(), result.reason.as_deref().unwrap_or("")));
            }
        }

        output
    }

    /// Generate console output
    pub fn to_console_output(&self) -> String {
        let (clean, suspicious, critical, known_bad) = self.summary();
        let total = self.results.len();

        let mut lines = vec![
            format!("Scanning: {} ({} files)", self.scan_path.display(), total),
            "─".repeat(60),
        ];

        for result in &self.results {
            let line = format!(
                "{} {} ({}, entropy: {:.1})",
                result.emoji(),
                result.path.file_name().unwrap_or_default().to_string_lossy(),
                result.class_description(),
                result.entropy.score
            );
            lines.push(line);

            if let Some(ref reason) = result.reason {
                lines.push(format!("   → {}", reason));
            }
        }

        lines.push("─".repeat(60));
        lines.push(format!(
            "Summary: {} clean, {} suspicious, {} critical, {} known bad",
            clean, suspicious, critical, known_bad
        ));

        lines.join("\n")
    }
}

/// Directory scanner
pub struct DirectoryScanner {
    /// Security mode
    mode: SecurityMode,
    /// Maximum recursion depth (None = unlimited)
    max_depth: Option<usize>,
    /// File classifier
    classifier: FileClassifier,
    /// Hash database (optional)
    hash_checker: Option<crate::threat::HashDB>,
}

impl DirectoryScanner {
    /// Create a new directory scanner
    pub fn new(mode: SecurityMode) -> Self {
        Self {
            mode,
            max_depth: None,
            classifier: FileClassifier::new(),
            hash_checker: None,
        }
    }

    /// Set maximum recursion depth
    pub fn with_max_depth(mut self, depth: usize) -> Self {
        self.max_depth = Some(depth);
        self
    }

    /// Enable hash database checking
    pub fn with_hash_db(mut self, db: crate::threat::HashDB) -> Self {
        self.hash_checker = Some(db);
        self
    }

    /// Scan a directory
    pub fn scan(&self, path: &Path) -> Result<ScanReport> {
        let mut report = ScanReport::new(path.to_path_buf(), self.mode);

        let mut files = Vec::new();
        Self::collect_files(path, 0, self.max_depth, &mut files)?;

        for file_path in &files {
            match self.scan_single_file(file_path) {
                Ok(result) => report.add_result(result),
                Err(e) => {
                    tracing::warn!("Failed to scan {}: {}", file_path.display(), e);
                }
            }
        }

        Ok(report)
    }

    /// Recursively collect files from a directory using std::fs
    fn collect_files(
        dir: &Path,
        current_depth: usize,
        max_depth: Option<usize>,
        files: &mut Vec<PathBuf>,
    ) -> Result<()> {
        // Skip if we've exceeded max depth
        if let Some(max) = max_depth {
            if current_depth > max {
                return Ok(());
            }
        }

        // Handle the case where `dir` is a file, not a directory
        if dir.is_file() {
            files.push(dir.to_path_buf());
            return Ok(());
        }

        let entries = std::fs::read_dir(dir)
            .with_context(|| format!("Failed to read directory: {}", dir.display()))?;

        for entry in entries {
            let entry = entry.context("Failed to read directory entry")?;
            let path = entry.path();

            if path.is_file() {
                files.push(path);
            } else if path.is_dir() {
                // Skip hidden directories and common non-interesting dirs
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    if name.starts_with('.') || name == "node_modules" || name == "target" {
                        continue;
                    }
                }
                Self::collect_files(&path, current_depth + 1, max_depth, files)?;
            }
        }

        Ok(())
    }

    /// Scan a single file
    fn scan_single_file(&self, path: &Path) -> Result<ScanResult> {
        // Classify file
        let classification = self.classifier.classify(path)?;

        // Check entropy
        let entropy = scan_file(path)?;

        // Check hash database if available
        let hash_status = if let Some(ref db) = self.hash_checker {
            match db.check_file(path) {
                Ok(crate::threat::HashStatus::KnownBad(entry)) => {
                    HashCheckResult::KnownBad {
                        name: entry.name.clone(),
                        family: entry.family.clone(),
                    }
                }
                Ok(crate::threat::HashStatus::Clean) => HashCheckResult::Clean,
                _ => HashCheckResult::Unknown,
            }
        } else {
            HashCheckResult::Unknown
        };

        // Determine verdict based on mode and findings
        let (verdict, reason) = self.determine_verdict(&classification, &entropy, &hash_status);

        Ok(ScanResult {
            path: path.to_path_buf(),
            file_class: classification.class,
            entropy,
            hash_status,
            verdict,
            reason,
        })
    }

    /// Determine verdict based on findings and mode
    fn determine_verdict(
        &self,
        classification: &ClassificationResult,
        entropy: &EntropyResult,
        hash_status: &HashCheckResult,
    ) -> (Verdict, Option<String>) {
        // Known bad always takes precedence (even in AUDIT mode — this is invariant)
        if let HashCheckResult::KnownBad { name, .. } = hash_status {
            return (Verdict::KnownBad, Some(format!("Hash match: {}", name)));
        }

        // In AUDIT mode, report findings but don't flag as Critical/Suspicious
        // The scan is purely informational in AUDIT mode
        if self.mode == SecurityMode::Audit {
            if !classification.extension_matches_magic {
                let real_type = format!("{:?}", classification.class);
                return (Verdict::Clean, Some(format!(
                    "[AUDIT] Extension mismatch → {}, entropy: {:.1}",
                    real_type, entropy.score
                )));
            }
            match entropy.verdict {
                EntropyVerdict::Critical(score) => {
                    return (Verdict::Clean, Some(format!(
                        "[AUDIT] High entropy ({:.2}): likely packed/encrypted", score
                    )));
                }
                EntropyVerdict::Suspicious(score) => {
                    return (Verdict::Clean, Some(format!(
                        "[AUDIT] Elevated entropy ({:.2}): may be compressed", score
                    )));
                }
                _ => {}
            }
            return (Verdict::Clean, None);
        }

        // Extension mismatch is always suspicious
        if !classification.extension_matches_magic {
            let real_type = format!("{:?}", classification.class);
            let reason = format!(
                "EXTENSION MISMATCH → {}, entropy: {:.1}",
                real_type, entropy.score
            );

            return match self.mode {
                SecurityMode::Hard => (Verdict::Critical, Some(reason)),
                _ => {
                    if entropy.verdict.is_critical() {
                        (Verdict::Critical, Some(reason))
                    } else {
                        (Verdict::Suspicious, Some(reason))
                    }
                }
            };
        }

        // Entropy-based verdicts
        match entropy.verdict {
            EntropyVerdict::Critical(score) => {
                let reason = format!("High entropy ({:.2}): likely packed/encrypted", score);
                match self.mode {
                    SecurityMode::Hard => (Verdict::Critical, Some(reason)),
                    _ => (Verdict::Suspicious, Some(reason)),
                }
            }
            EntropyVerdict::Suspicious(score) => {
                let reason = format!("Elevated entropy ({:.2}): may be compressed", score);
                (Verdict::Suspicious, Some(reason))
            }
            EntropyVerdict::Clean => (Verdict::Clean, None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_report_summary() {
        let mut report = ScanReport::new(PathBuf::from("/test"), SecurityMode::Mid);

        report.add_result(ScanResult {
            path: PathBuf::from("/test/file1.txt"),
            file_class: crate::classifier::magic::FileClass::Unknown,
            entropy: EntropyResult::from_score(3.0, 100),
            hash_status: HashCheckResult::Clean,
            verdict: Verdict::Clean,
            reason: None,
        });

        report.add_result(ScanResult {
            path: PathBuf::from("/test/file2.bin"),
            file_class: crate::classifier::magic::FileClass::Binary,
            entropy: EntropyResult::from_score(7.5, 100),
            hash_status: HashCheckResult::Clean,
            verdict: Verdict::Critical,
            reason: Some("High entropy".to_string()),
        });

        let (clean, suspicious, critical, known_bad) = report.summary();
        assert_eq!(clean, 1);
        assert_eq!(suspicious, 0);
        assert_eq!(critical, 1);
        assert_eq!(known_bad, 0);
    }

    #[test]
    fn test_verdict_display() {
        assert_eq!(Verdict::Clean.to_string(), "CLEAN");
        assert_eq!(Verdict::Suspicious.to_string(), "SUSPICIOUS");
        assert_eq!(Verdict::Critical.to_string(), "CRITICAL");
        assert_eq!(Verdict::KnownBad.to_string(), "KNOWN BAD");
    }
}
