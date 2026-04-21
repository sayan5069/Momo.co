//! BORU Scanner — File analysis and detection utilities
//!
//! This module provides:
//! - Entropy scanning for packed/obfuscated detection
//! - Directory scanning for batch analysis

pub mod entropy;
pub mod dirscan;

pub use entropy::{EntropyResult, EntropyVerdict, scan_file, scan_bytes};
pub use dirscan::{DirectoryScanner, ScanResult, ScanReport, Verdict, HashCheckResult};
