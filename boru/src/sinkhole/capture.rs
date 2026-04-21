//! BORU Sinkhole Capture — Local inbound listener for blocked network traffic
//!
//! GATE 4: This is a LOCAL inbound listener ONLY.
//! // MOMO-NETWORK-ALLOWED (localhost inbound only)
//! It NEVER forwards traffic — it captures and logs.

use super::{CapturedConnection, ProtocolType, SinkholeConfig};
use anyhow::{Context, Result};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Sinkhole server — captures blocked network traffic
/// // MOMO-NETWORK-ALLOWED (localhost inbound only)
pub struct SinkholeServer {
    config: SinkholeConfig,
    running: Arc<AtomicBool>,
    captures: Arc<std::sync::Mutex<Vec<CapturedConnection>>>,
}

impl SinkholeServer {
    /// Create a new sinkhole server
    pub fn new(config: SinkholeConfig) -> Result<Self> {
        // Ensure capture directory exists
        std::fs::create_dir_all(&config.capture_dir)
            .with_context(|| format!("Failed to create capture dir: {}", config.capture_dir.display()))?;

        Ok(Self {
            config,
            running: Arc::new(AtomicBool::new(false)),
            captures: Arc::new(std::sync::Mutex::new(Vec::new())),
        })
    }

    /// Start the sinkhole listener on localhost
    /// // MOMO-NETWORK-ALLOWED (localhost inbound only)
    pub fn start(&self, port: u16) -> Result<()> {
        // CRITICAL: Only bind to localhost — never 0.0.0.0
        let bind_addr = format!("127.0.0.1:{}", port);
        let listener = TcpListener::bind(&bind_addr)
            .with_context(|| format!("Failed to bind sinkhole: {}", bind_addr))?;

        // Set non-blocking so we can check the running flag
        listener.set_nonblocking(true)?;

        self.running.store(true, Ordering::SeqCst);

        let request_id = uuid::Uuid::new_v4();
        crate::cage::log_intercept(
            crate::cage::Severity::Medium,
            "SINKHOLE_STARTED",
            &format!("Sinkhole listening on {}", bind_addr),
            request_id,
        );

        while self.running.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((stream, addr)) => {
                    let capture = self.handle_connection(stream, &addr.to_string());
                    if let Ok(captured) = capture {
                        if let Ok(mut captures) = self.captures.lock() {
                            // GATE 6: Bounded buffer — max 1000 captures
                            if captures.len() >= 1000 {
                                captures.remove(0);
                            }
                            captures.push(captured);
                        }
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // No connection pending — sleep briefly
                    std::thread::sleep(Duration::from_millis(100));
                }
                Err(e) => {
                    tracing::warn!("Sinkhole accept error: {}", e);
                }
            }
        }

        Ok(())
    }

    /// Stop the sinkhole
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    /// Handle a single connection — capture payload
    fn handle_connection(
        &self,
        mut stream: TcpStream,
        intended_dest: &str,
    ) -> Result<CapturedConnection> {
        // Set read timeout
        stream.set_read_timeout(Some(Duration::from_secs(self.config.timeout_secs)))?;

        // Read payload
        let mut payload = vec![0u8; self.config.max_payload_size];
        let bytes_read = stream.read(&mut payload).unwrap_or(0);
        payload.truncate(bytes_read);

        // Detect protocol
        let protocol = Self::detect_protocol(&payload);

        // Create capture ID
        let capture_id = uuid::Uuid::new_v4().to_string();

        // Save payload to file
        let payload_file = self.config.capture_dir.join(format!("{}.bin", capture_id));
        std::fs::write(&payload_file, &payload)
            .with_context(|| format!("Failed to write payload: {}", payload_file.display()))?;

        // Create hex preview (first 256 bytes)
        let preview_bytes = std::cmp::min(payload.len(), 256);
        let payload_preview = payload[..preview_bytes]
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ");

        // Try to detect hostname from HTTP payload
        let intended_host = Self::extract_host(&payload);

        let captured = CapturedConnection {
            capture_id,
            timestamp: chrono::Utc::now().to_rfc3339(),
            intended_destination: intended_dest.to_string(),
            intended_host,
            protocol_detected: protocol.clone(),
            payload_bytes: bytes_read,
            payload_preview,
            payload_file: payload_file.clone(),
            verdict: "CAPTURED_AND_BLOCKED".to_string(),
        };

        // Log the capture — GATE 7: audit before verdict
        let request_id = uuid::Uuid::new_v4();
        crate::cage::log_intercept(
            crate::cage::Severity::High,
            "SINKHOLE_CAPTURE",
            &format!(
                "Captured {} traffic to {} ({} bytes)",
                protocol, intended_dest, bytes_read
            ),
            request_id,
        );

        // Send a reset/close — never forward
        let _ = stream.shutdown(std::net::Shutdown::Both);

        Ok(captured)
    }

    /// Detect protocol from payload bytes
    fn detect_protocol(payload: &[u8]) -> ProtocolType {
        if payload.is_empty() {
            return ProtocolType::Unknown;
        }

        // HTTP detection
        if payload.starts_with(b"GET ")
            || payload.starts_with(b"POST ")
            || payload.starts_with(b"PUT ")
            || payload.starts_with(b"DELETE ")
            || payload.starts_with(b"HEAD ")
            || payload.starts_with(b"OPTIONS ")
            || payload.starts_with(b"PATCH ")
        {
            return ProtocolType::Http;
        }

        // TLS/HTTPS detection (TLS handshake starts with 0x16 0x03)
        if payload.len() >= 2 && payload[0] == 0x16 && payload[1] == 0x03 {
            return ProtocolType::Https;
        }

        // DNS detection (simple — port-based is more reliable, but check payload structure)
        if payload.len() >= 12 {
            // DNS has a 12-byte header, check for typical flags
            let flags = ((payload[2] as u16) << 8) | payload[3] as u16;
            let qr = (flags >> 15) & 1;
            let opcode = (flags >> 11) & 0xF;
            if qr == 0 && opcode <= 2 {
                // Looks like a DNS query
                return ProtocolType::Dns;
            }
        }

        ProtocolType::RawTcp
    }

    /// Extract Host header from HTTP payload
    fn extract_host(payload: &[u8]) -> Option<String> {
        let text = String::from_utf8_lossy(payload);
        for line in text.lines() {
            let lower = line.to_lowercase();
            if lower.starts_with("host:") {
                return Some(line[5..].trim().to_string());
            }
        }
        None
    }

    /// Get all captures
    pub fn captures(&self) -> Vec<CapturedConnection> {
        self.captures.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Get capture count
    pub fn capture_count(&self) -> usize {
        self.captures.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_protocol_http() {
        assert_eq!(SinkholeServer::detect_protocol(b"GET / HTTP/1.1"), ProtocolType::Http);
        assert_eq!(SinkholeServer::detect_protocol(b"POST /api"), ProtocolType::Http);
    }

    #[test]
    fn test_detect_protocol_tls() {
        let tls_hello = [0x16, 0x03, 0x01, 0x00, 0x05];
        assert_eq!(SinkholeServer::detect_protocol(&tls_hello), ProtocolType::Https);
    }

    #[test]
    fn test_detect_protocol_empty() {
        assert_eq!(SinkholeServer::detect_protocol(b""), ProtocolType::Unknown);
    }

    #[test]
    fn test_extract_host() {
        let payload = b"GET / HTTP/1.1\r\nHost: evil.com\r\n\r\n";
        let host = SinkholeServer::extract_host(payload);
        assert_eq!(host, Some("evil.com".to_string()));
    }

    #[test]
    fn test_extract_host_missing() {
        let payload = b"random data";
        assert_eq!(SinkholeServer::extract_host(payload), None);
    }
}
