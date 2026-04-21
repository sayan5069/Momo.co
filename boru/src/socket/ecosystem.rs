//! BORU Ecosystem Integration — Auto-discovery and communication with MOMO siblings
//!
//! Unix Philosophy: Discover siblings via filesystem sockets, not localhost ports.
//! If siblings are present → collaborate. If not → work standalone.
//!
//! Pattern: " boru check --input file.rs " works alone.
//!          When suji is present, it calls boru via socket and renders results.
//!          When nuki is present, boru queries it for file context.

use crate::cage::policy::SecurityMode;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Ecosystem service capability advertisement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceCapabilities {
    pub service: String,
    pub version: String,
    pub features: Vec<String>,
    pub mode: String,
}

/// Event broadcast to siblings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EcosystemEvent {
    pub source: String,
    pub event_type: String,
    pub severity: String,
    pub message: String,
    pub path: Option<String>,
    pub timestamp: String,
}

/// Context request to Nuki
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NukiContextRequest {
    pub file_path: String,
}

/// Context response from Nuki
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NukiContextResponse {
    pub file_path: String,
    pub references: Vec<String>,
    pub language: Option<String>,
    pub context_summary: Option<String>,
}

/// Check full ecosystem status
pub fn status() -> EcosystemStatus {
    super::config::ecosystem_status()
}

/// Query Nuki for file context (if available)
pub async fn query_nuki_context(file_path: &Path) -> Option<NukiContextResponse> {
    if !super::config::nuki_available() {
        return None;
    }

    #[cfg(unix)]
    {
        match query_nuki_unix(file_path).await {
            Ok(resp) => Some(resp),
            Err(e) => {
                tracing::debug!("Failed to query Nuki: {}", e);
                None
            }
        }
    }

    #[cfg(windows)]
    {
        // Windows: Nuki would use TCP localhost
        None // TODO: Implement Windows discovery
    }
}

#[cfg(unix)]
async fn query_nuki_unix(file_path: &Path) -> Result<NukiContextResponse> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixStream;

    let request = NukiContextRequest {
        file_path: file_path.to_string_lossy().to_string(),
    };

    let mut stream = UnixStream::connect(super::config::NUKI_SOCKET_PATH)
        .await
        .context("Failed to connect to Nuki socket")?;

    let request_bytes = serde_json::to_vec(&request)?;
    stream.write_all(&request_bytes).await?;
    stream.write_all(b"\n").await?;
    stream.flush().await?;

    // Read response
    let mut buffer = vec![0u8; 65536];
    let n = stream.read(&mut buffer).await?;
    buffer.truncate(n);

    let response: NukiContextResponse = serde_json::from_slice(&buffer)?;
    Ok(response)
}

/// Notify Suji of an event (if available)
pub async fn notify_suji(event: EcosystemEvent) {
    if !super::config::suji_available() {
        return;
    }

    #[cfg(unix)]
    {
        if let Err(e) = notify_suji_unix(event).await {
            tracing::debug!("Failed to notify Suji: {}", e);
        }
    }
}

#[cfg(unix)]
async fn notify_suji_unix(event: EcosystemEvent) -> Result<()> {
    use tokio::io::AsyncWriteExt;
    use tokio::net::UnixStream;

    let mut stream = UnixStream::connect(super::config::SUJI_SOCKET_PATH)
        .await
        .context("Failed to connect to Suji socket")?;

    let event_bytes = serde_json::to_vec(&event)?;
    stream.write_all(&event_bytes).await?;
    stream.write_all(b"\n").await?;
    stream.flush().await?;

    Ok(())
}

/// Broadcast a security event to all siblings
pub async fn broadcast_event(event_type: &str, severity: &str, message: &str, path: Option<&Path>) {
    let event = EcosystemEvent {
        source: "boru".to_string(),
        event_type: event_type.to_string(),
        severity: severity.to_string(),
        message: message.to_string(),
        path: path.map(|p| p.to_string_lossy().to_string()),
        timestamp: chrono::Utc::now().to_rfc3339(),
    };

    // Notify Suji if available
    notify_suji(event).await;
}

/// Format capabilities for service advertisement
pub fn get_capabilities(mode: SecurityMode) -> ServiceCapabilities {
    ServiceCapabilities {
        service: "boru".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        features: vec![
            "scan".to_string(),
            "cage".to_string(),
            "watchdog".to_string(),
            "quarantine".to_string(),
            "audit".to_string(),
            "rollback".to_string(),
        ],
        mode: format!("{:?}", mode),
    }
}

/// Check if running in standalone mode (no siblings)
pub fn standalone_mode() -> bool {
    let status = status();
    !status.nuki && !status.suji
}

/// Log ecosystem integration status
pub fn log_status() {
    let status = status();

    tracing::info!("MOMO Ecosystem Status:");
    tracing::info!("  BORU (this): active");
    tracing::info!("  NUKI: {}", if status.nuki { "connected" } else { "not detected" });
    tracing::info!("  SUJI: {}", if status.suji { "connected" } else { "not detected" });

    if standalone_mode() {
        tracing::info!("Mode: STANDALONE (no siblings detected)");
    } else {
        tracing::info!("Mode: ECOSYSTEM ({} services active)", status.service_count());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_standalone_detection() {
        // Just verify the function runs
        let _ = standalone_mode();
    }

    #[test]
    fn test_get_capabilities() {
        let caps = get_capabilities(SecurityMode::Audit);
        assert_eq!(caps.service, "boru");
        assert!(caps.features.contains(&"scan".to_string()));
    }

    #[test]
    fn test_ecosystem_event_serialization() {
        let event = EcosystemEvent {
            source: "boru".to_string(),
            event_type: "FILE_BLOCKED".to_string(),
            severity: "CRITICAL".to_string(),
            message: "Test message".to_string(),
            path: Some("/test.txt".to_string()),
            timestamp: "2024-01-01T00:00:00Z".to_string(),
        };

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("FILE_BLOCKED"));
        assert!(json.contains("boru"));
    }
}
