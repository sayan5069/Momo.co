//! BORU Socket Configuration
//!
//! GATE 3: All socket paths centralized here. No hardcoded paths elsewhere.
//!
//! Socket paths for Project MOMO Ecosystem:
//! - BORU: /tmp/momo/boru.sock (security engine)
//! - NUKI: /tmp/momo/nuki.sock (search/memory engine)
//! - SUJI: /tmp/momo/suji.sock (orchestrator/conductor)
//! - ZUNO: /tmp/momo/zuno.sock (indexer - Phase 2 stub)
//! - SABA: /tmp/momo/saba.sock (router - Phase 2 stub)
//!
//! Unix Philosophy: Auto-discover siblings via filesystem sockets.
//! No hardcoded ports. No localhost HTTP. Pure Unix sockets.

use std::path::Path;

/// Default BORU socket path
pub const BORU_SOCKET_PATH: &str = "/tmp/momo/boru.sock";

/// NUKI socket path (search engine - auto-detected)
pub const NUKI_SOCKET_PATH: &str = "/tmp/momo/nuki.sock";

/// SUJI socket path (orchestrator - auto-detected)
pub const SUJI_SOCKET_PATH: &str = "/tmp/momo/suji.sock";

/// ZUNO socket path (Phase 2 - stub only)
#[allow(dead_code)]
pub const ZUNO_SOCKET_PATH: &str = "/tmp/momo/zuno.sock";

/// SABA socket path (Phase 2 - stub only)
#[allow(dead_code)]
pub const SABA_SOCKET_PATH: &str = "/tmp/momo/saba.sock";

/// Maximum request size: 10MB
pub const MAX_REQUEST_SIZE: usize = 10 * 1024 * 1024;

/// Socket directory path
pub const SOCKET_DIR: &str = "/tmp/momo";

/// BORU workspace directory for sandbox file operations
#[allow(dead_code)]
pub const BORU_WORKSPACE_DIR: &str = "/tmp/momo/workspace";

/// Service discovery: Check if a sibling service is running
pub fn is_service_available(socket_path: &str) -> bool {
    Path::new(socket_path).exists()
}

/// Check if NUKI (search engine) is available
pub fn nuki_available() -> bool {
    is_service_available(NUKI_SOCKET_PATH)
}

/// Check if SUJI (orchestrator) is available
pub fn suji_available() -> bool {
    is_service_available(SUJI_SOCKET_PATH)
}

/// Get ecosystem status - which siblings are present
pub fn ecosystem_status() -> EcosystemStatus {
    EcosystemStatus {
        boru: true, // We're here
        nuki: nuki_available(),
        suji: suji_available(),
        zuno: is_service_available(ZUNO_SOCKET_PATH),
        saba: is_service_available(SABA_SOCKET_PATH),
    }
}

/// Ecosystem presence detection
#[derive(Debug, Clone)]
pub struct EcosystemStatus {
    pub boru: bool,
    pub nuki: bool,
    pub suji: bool,
    pub zuno: bool,
    pub saba: bool,
}

impl EcosystemStatus {
    /// Check if we're running in full MOMO ecosystem mode
    pub fn full_ecosystem() -> bool {
        let status = ecosystem_status();
        status.boru && status.nuki && status.suji
    }

    /// Get count of available services
    pub fn service_count(&self) -> usize {
        let mut count = 0;
        if self.boru { count += 1; }
        if self.nuki { count += 1; }
        if self.suji { count += 1; }
        if self.zuno { count += 1; }
        if self.saba { count += 1; }
        count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_socket_paths() {
        assert_eq!(BORU_SOCKET_PATH, "/tmp/momo/boru.sock");
        assert_eq!(NUKI_SOCKET_PATH, "/tmp/momo/nuki.sock");
        assert_eq!(SUJI_SOCKET_PATH, "/tmp/momo/suji.sock");
    }

    #[test]
    fn test_ecosystem_status() {
        // Just verify it doesn't panic
        let status = ecosystem_status();
        assert!(status.boru); // We exist
        // Other values depend on runtime state
    }
}
