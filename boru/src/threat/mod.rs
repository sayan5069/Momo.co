//! BORU Threat Intelligence — Malware detection and hash database
//!
//! Provides:
//! - Local hash database for known malware detection
//! - Offline threat intelligence (no cloud dependencies)

pub mod hashdb;

pub use hashdb::{HashDB, HashEntry, HashStatus, Severity, compute_file_hash, compute_bytes_hash};
