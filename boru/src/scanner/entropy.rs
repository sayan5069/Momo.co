//! BORU Entropy Scanner — Shannon entropy detection for packed/obfuscated files
//!
//! High entropy = likely encrypted, packed, or obfuscated = suspicious.
//!
//! Thresholds:
//! - ENTROPY_CRITICAL: 7.2 — packed binary / ransomware dropper
//! - ENTROPY_WARN: 6.5 — compressed or minified, flag it
//! - ENTROPY_NORMAL: below 6.5 — clean

use anyhow::{Context, Result};
use std::path::Path;

const ENTROPY_CRITICAL: f64 = 7.2;
const ENTROPY_WARN: f64 = 6.5;
const SAMPLE_SIZE: usize = 8192;

/// Entropy verdict
#[derive(Debug, Clone, PartialEq)]
pub enum EntropyVerdict {
    /// Clean entropy level
    Clean,
    /// Suspicious — elevated but not critical
    Suspicious(f64),
    /// Critical — likely packed/encrypted
    Critical(f64),
}

impl EntropyVerdict {
    /// Get the entropy score if available
    pub fn score(&self) -> Option<f64> {
        match self {
            EntropyVerdict::Clean => None,
            EntropyVerdict::Suspicious(s) | EntropyVerdict::Critical(s) => Some(*s),
        }
    }

    /// Check if this is a critical verdict
    pub fn is_critical(&self) -> bool {
        matches!(self, EntropyVerdict::Critical(_))
    }

    /// Check if this is suspicious or worse
    pub fn is_suspicious(&self) -> bool {
        matches!(self, EntropyVerdict::Suspicious(_) | EntropyVerdict::Critical(_))
    }
}

impl std::fmt::Display for EntropyVerdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EntropyVerdict::Clean => write!(f, "Clean"),
            EntropyVerdict::Suspicious(score) => write!(f, "Suspicious ({:.2})", score),
            EntropyVerdict::Critical(score) => write!(f, "Critical ({:.2})", score),
        }
    }
}

/// Entropy scan result
#[derive(Debug, Clone)]
pub struct EntropyResult {
    /// Entropy score (0-8 for bytes)
    pub score: f64,
    /// Verdict based on thresholds
    pub verdict: EntropyVerdict,
    /// Number of bytes sampled
    pub bytes_sampled: usize,
}

impl EntropyResult {
    /// Create a new entropy result from a score
    pub fn from_score(score: f64, bytes_sampled: usize) -> Self {
        let verdict = if score >= ENTROPY_CRITICAL {
            EntropyVerdict::Critical(score)
        } else if score >= ENTROPY_WARN {
            EntropyVerdict::Suspicious(score)
        } else {
            EntropyVerdict::Clean
        };

        Self {
            score,
            verdict,
            bytes_sampled,
        }
    }

    /// Get a user-friendly description
    pub fn description(&self) -> &'static str {
        match self.verdict {
            EntropyVerdict::Clean => "Normal entropy — likely legitimate file",
            EntropyVerdict::Suspicious(_) => "Elevated entropy — may be compressed or minified",
            EntropyVerdict::Critical(_) => "High entropy — likely packed, encrypted, or obfuscated",
        }
    }
}

impl std::fmt::Display for EntropyResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Entropy: {:.2}/8.0 — {} (sampled {} bytes)",
            self.score, self.verdict, self.bytes_sampled
        )
    }
}

/// Calculate Shannon entropy of a byte slice
///
/// H = -sum(p(x) * log2(p(x))) for each unique byte value x
/// p(x) = count of byte x / total bytes
pub fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    // Count occurrences of each byte value
    let mut counts = [0u64; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }

    let total = data.len() as f64;
    let mut entropy = 0.0;

    // Calculate Shannon entropy
    for &count in &counts {
        if count > 0 {
            let probability = count as f64 / total;
            entropy -= probability * probability.log2();
        }
    }

    entropy
}

/// Scan a file for entropy
///
/// Reads first SAMPLE_SIZE bytes and calculates Shannon entropy.
/// Returns EntropyResult with verdict based on thresholds.
pub fn scan_file(path: &Path) -> Result<EntropyResult> {
    use std::io::Read;

    let file = std::fs::File::open(path)
        .with_context(|| format!("Failed to open file for entropy scan: {}", path.display()))?;

    let mut buffer = vec![0u8; SAMPLE_SIZE];
    let mut reader = std::io::BufReader::new(file);
    let bytes_read = reader
        .read(&mut buffer)
        .with_context(|| format!("Failed to read file for entropy scan: {}", path.display()))?;

    buffer.truncate(bytes_read);

    let score = calculate_entropy(&buffer);

    Ok(EntropyResult::from_score(score, bytes_read))
}

/// Scan raw bytes for entropy
pub fn scan_bytes(data: &[u8]) -> EntropyResult {
    let sample = if data.len() > SAMPLE_SIZE {
        &data[..SAMPLE_SIZE]
    } else {
        data
    };

    let score = calculate_entropy(sample);
    EntropyResult::from_score(score, sample.len())
}

/// Get threshold values
pub fn thresholds() -> (f64, f64) {
    (ENTROPY_WARN, ENTROPY_CRITICAL)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_empty() {
        let entropy = calculate_entropy(b"");
        assert_eq!(entropy, 0.0);
    }

    #[test]
    fn test_entropy_uniform() {
        // All same byte = 0 entropy
        let data = vec![0x41u8; 1000];
        let entropy = calculate_entropy(&data);
        assert!(entropy < 0.01);
    }

    #[test]
    fn test_entropy_random_like() {
        // High entropy (uniform distribution)
        let data: Vec<u8> = (0..=255).cycle().take(1000).collect();
        let entropy = calculate_entropy(&data);
        // Should be near maximum (8.0 for bytes)
        assert!(entropy > 7.0, "Expected high entropy, got {}", entropy);
    }

    #[test]
    fn test_entropy_english_text() {
        // English text has relatively low entropy (~4.5)
        let text = b"The quick brown fox jumps over the lazy dog. ".repeat(20);
        let entropy = calculate_entropy(&text[..]);
        assert!(entropy > 3.0 && entropy < 6.0, "English text entropy should be moderate, got {}", entropy);
    }

    #[test]
    fn test_verdict_clean() {
        let result = EntropyResult::from_score(4.0, 1000);
        assert!(matches!(result.verdict, EntropyVerdict::Clean));
        assert!(!result.verdict.is_suspicious());
        assert!(!result.verdict.is_critical());
    }

    #[test]
    fn test_verdict_suspicious() {
        let result = EntropyResult::from_score(6.8, 1000);
        assert!(matches!(result.verdict, EntropyVerdict::Suspicious(6.8)));
        assert!(result.verdict.is_suspicious());
        assert!(!result.verdict.is_critical());
    }

    #[test]
    fn test_verdict_critical() {
        let result = EntropyResult::from_score(7.5, 1000);
        assert!(matches!(result.verdict, EntropyVerdict::Critical(7.5)));
        assert!(result.verdict.is_suspicious());
        assert!(result.verdict.is_critical());
    }

    #[test]
    fn test_scan_bytes() {
        let data = vec![0u8; 100]; // Low entropy
        let result = scan_bytes(&data);
        assert!(matches!(result.verdict, EntropyVerdict::Clean));
    }

    #[test]
    fn test_thresholds() {
        let (warn, critical) = thresholds();
        assert_eq!(warn, 6.5);
        assert_eq!(critical, 7.2);
    }
}
