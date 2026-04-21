//! BORU Network Sinkhole — Capture blocked network traffic
//!
//! Instead of dropping blocked network connections,
//! BORU routes them to a local dummy server (sinkhole).
//! The sinkhole captures the full payload — what the AI was trying to send.
//! This turns a block into threat intelligence.
//!
//! GATE 4: This uses a LOCAL inbound listener only.
//! // MOMO-NETWORK-ALLOWED (localhost inbound only)

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;

pub mod capture;
pub mod report;

pub use capture::SinkholeServer;
pub use report::CaptureReport;

/// Sinkhole configuration
#[derive(Debug, Clone)]
pub struct SinkholeConfig {
    /// Maximum payload size to capture (default 64KB)
    pub max_payload_size: usize,
    /// Timeout in seconds (default 5)
    pub timeout_secs: u64,
    /// Storage directory for captures
    pub capture_dir: PathBuf,
    /// Protocol detection enabled
    pub detect_protocols: bool,
}

impl SinkholeConfig {
    /// Create default config
    pub fn new() -> Result<Self> {
        let capture_dir = dirs::data_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("boru")
            .join("captures");

        Ok(Self {
            max_payload_size: 64 * 1024, // 64KB
            timeout_secs: 5,
            capture_dir,
            detect_protocols: true,
        })
    }

    /// Set max payload size
    pub fn with_max_payload_size(mut self, size: usize) -> Self {
        self.max_payload_size = size;
        self
    }

    /// Set timeout
    pub fn with_timeout(mut self, secs: u64) -> Self {
        self.timeout_secs = secs;
        self
    }

    /// Set capture directory
    pub fn with_capture_dir(mut self, dir: PathBuf) -> Self {
        self.capture_dir = dir;
        self
    }
}

impl Default for SinkholeConfig {
    fn default() -> Self {
        Self::new().expect("Failed to create default SinkholeConfig")
    }
}

/// Detected protocol type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ProtocolType {
    Http,
    Https,
    Dns,
    RawTcp,
    Unknown,
}

impl std::fmt::Display for ProtocolType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProtocolType::Http => write!(f, "HTTP"),
            ProtocolType::Https => write!(f, "HTTPS"),
            ProtocolType::Dns => write!(f, "DNS"),
            ProtocolType::RawTcp => write!(f, "Raw TCP"),
            ProtocolType::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Captured connection data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapturedConnection {
    /// Capture ID (UUID)
    pub capture_id: String,
    /// Timestamp (ISO-8601)
    pub timestamp: String,
    /// Intended destination (original target)
    pub intended_destination: String,
    /// Intended hostname (if detectable)
    pub intended_host: Option<String>,
    /// Detected protocol
    pub protocol_detected: ProtocolType,
    /// Payload size in bytes
    pub payload_bytes: usize,
    /// Payload preview (first 256 bytes as hex)
    pub payload_preview: String,
    /// Path to full payload file
    pub payload_file: PathBuf,
    /// Verdict
    pub verdict: String,
}

/// Sinkhole statistics
#[derive(Debug, Clone)]
pub struct SinkholeStats {
    /// Total connections captured
    pub total_captured: usize,
    /// HTTP connections
    pub http_count: usize,
    /// HTTPS connections
    pub https_count: usize,
    /// DNS queries
    pub dns_count: usize,
    /// Raw TCP
    pub tcp_count: usize,
}

/// Check if sinkhole should be used for this mode
pub fn should_sinkhole(mode: crate::cage::policy::SecurityMode) -> bool {
    // HARD mode: DROP immediately. No sinkhole.
    // MID/EASY/CUSTOM: Route to sinkhole then BLOCK
    // AUDIT: Route to sinkhole, capture, then ALLOW (full intelligence)
    !matches!(mode, crate::cage::policy::SecurityMode::Hard)
}

/// Get sinkhole verdict for this mode
pub fn sinkhole_verdict(mode: crate::cage::policy::SecurityMode) -> &'static str {
    match mode {
        crate::cage::policy::SecurityMode::Hard => "DROPPED",
        crate::cage::policy::SecurityMode::Audit => "SINKHOLED_OBSERVED",
        _ => "SINKHOLED_BLOCKED",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cage::policy::SecurityMode;

    #[test]
    fn test_should_sinkhole() {
        assert!(!should_sinkhole(SecurityMode::Hard));
        assert!(should_sinkhole(SecurityMode::Mid));
        assert!(should_sinkhole(SecurityMode::Easy));
        assert!(should_sinkhole(SecurityMode::Custom));
        assert!(should_sinkhole(SecurityMode::Audit));
    }

    #[test]
    fn test_sinkhole_verdict() {
        assert_eq!(sinkhole_verdict(SecurityMode::Hard), "DROPPED");
        assert_eq!(sinkhole_verdict(SecurityMode::Mid), "SINKHOLED_BLOCKED");
        assert_eq!(sinkhole_verdict(SecurityMode::Easy), "SINKHOLED_BLOCKED");
        assert_eq!(sinkhole_verdict(SecurityMode::Custom), "SINKHOLED_BLOCKED");
        assert_eq!(sinkhole_verdict(SecurityMode::Audit), "SINKHOLED_OBSERVED");
    }

    #[test]
    fn test_protocol_type_display() {
        assert_eq!(ProtocolType::Http.to_string(), "HTTP");
        assert_eq!(ProtocolType::Https.to_string(), "HTTPS");
        assert_eq!(ProtocolType::Dns.to_string(), "DNS");
    }
}
