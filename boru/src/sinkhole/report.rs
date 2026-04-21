//! BORU Sinkhole Report — Capture report generation
//!
//! Generates human-readable reports from sinkhole captures.
//! Shows what AI agents tried to exfiltrate.

use super::CapturedConnection;
use anyhow::{Context, Result};
use std::path::Path;

/// Capture report generator
pub struct CaptureReport;

impl CaptureReport {
    /// Generate markdown report from captures
    pub fn to_markdown(captures: &[CapturedConnection]) -> String {
        if captures.is_empty() {
            return "# BORU Sinkhole Report\n\nNo captures recorded.\n".to_string();
        }

        let mut output = format!(
            "# BORU Sinkhole Report\n\nTotal captures: {}\n\n## Captured Connections\n\n| ID | Time | Protocol | Destination | Size | Verdict |\n|-----|------|---------|-------------|------|---------|\n",
            captures.len()
        );

        for cap in captures {
            let short_id = &cap.capture_id[..8.min(cap.capture_id.len())];
            let time = if cap.timestamp.len() >= 19 {
                &cap.timestamp[11..19]
            } else {
                &cap.timestamp
            };

            output.push_str(&format!(
                "| {}... | {} | {} | {} | {} B | {} |\n",
                short_id,
                time,
                cap.protocol_detected,
                cap.intended_host.as_deref().unwrap_or(&cap.intended_destination),
                cap.payload_bytes,
                cap.verdict,
            ));
        }

        // Protocol breakdown
        let http = captures.iter().filter(|c| matches!(c.protocol_detected, super::ProtocolType::Http)).count();
        let https = captures.iter().filter(|c| matches!(c.protocol_detected, super::ProtocolType::Https)).count();
        let dns = captures.iter().filter(|c| matches!(c.protocol_detected, super::ProtocolType::Dns)).count();
        let tcp = captures.iter().filter(|c| matches!(c.protocol_detected, super::ProtocolType::RawTcp)).count();
        let unknown = captures.iter().filter(|c| matches!(c.protocol_detected, super::ProtocolType::Unknown)).count();

        output.push_str(&format!(
            "\n## Protocol Breakdown\n\n- HTTP: {}\n- HTTPS: {}\n- DNS: {}\n- Raw TCP: {}\n- Unknown: {}\n",
            http, https, dns, tcp, unknown
        ));

        output
    }

    /// Generate console output
    pub fn to_console(captures: &[CapturedConnection]) -> String {
        if captures.is_empty() {
            return "No sinkhole captures recorded.".to_string();
        }

        let mut lines = vec![
            format!("BORU Sinkhole — {} captures", captures.len()),
            "─".repeat(70),
        ];

        for cap in captures {
            let short_id = &cap.capture_id[..8.min(cap.capture_id.len())];
            let time = if cap.timestamp.len() >= 19 {
                &cap.timestamp[11..19]
            } else {
                &cap.timestamp
            };

            lines.push(format!(
                "  {}  {} → {} | {} | {} bytes",
                short_id,
                time,
                cap.intended_host.as_deref().unwrap_or(&cap.intended_destination),
                cap.protocol_detected,
                cap.payload_bytes,
            ));
        }

        lines.push("─".repeat(70));
        lines.join("\n")
    }

    /// Save report to file
    pub fn save_markdown(captures: &[CapturedConnection], path: &Path) -> Result<()> {
        let report = Self::to_markdown(captures);

        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        std::fs::write(path, report)
            .with_context(|| format!("Failed to write sinkhole report: {}", path.display()))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::ProtocolType;

    #[test]
    fn test_empty_report() {
        let report = CaptureReport::to_markdown(&[]);
        assert!(report.contains("No captures"));
    }

    #[test]
    fn test_console_empty() {
        let output = CaptureReport::to_console(&[]);
        assert!(output.contains("No sinkhole captures"));
    }

    #[test]
    fn test_report_with_capture() {
        let captures = vec![CapturedConnection {
            capture_id: "test-id-12345678".to_string(),
            timestamp: "2024-01-01T12:00:00Z".to_string(),
            intended_destination: "1.2.3.4:443".to_string(),
            intended_host: Some("evil.com".to_string()),
            protocol_detected: ProtocolType::Https,
            payload_bytes: 1024,
            payload_preview: "16 03 01".to_string(),
            payload_file: std::path::PathBuf::from("/tmp/test.bin"),
            verdict: "CAPTURED_AND_BLOCKED".to_string(),
        }];

        let report = CaptureReport::to_markdown(&captures);
        assert!(report.contains("evil.com"));
        assert!(report.contains("HTTPS"));
        assert!(report.contains("1024"));
    }
}
