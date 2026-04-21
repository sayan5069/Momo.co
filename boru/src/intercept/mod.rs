//! BORU Intercept — Syscall/file/network intercept rules
//!
//! This module defines all interception policies. No bare execution
//! outside this module and the cage.
//!
//! GATE 7: Every blocked action writes to audit log BEFORE returning verdict.

#![allow(dead_code)]

use crate::cage;
use crate::cage::policy::{PolicyDecision, SecurityMode, SecurityPolicy};
use crate::classifier::ClassificationResult;

pub mod audit;
pub mod quarantine;

/// Intercept verdict
#[derive(Debug, Clone, PartialEq)]
pub enum Verdict {
    Allowed,
    Blocked { reason: String },
    Prompt { reason: String },
    Quarantined { path: std::path::PathBuf, reason: String },
}

/// Intercept event types
#[derive(Debug, Clone)]
pub enum InterceptEvent {
    /// File read operation
    FileRead {
        path: std::path::PathBuf,
        outside_workspace: bool,
    },
    /// File write operation
    FileWrite {
        path: std::path::PathBuf,
        outside_workspace: bool,
    },
    /// Network access attempt
    NetworkAccess {
        destination: Option<String>,
    },
    /// Process execution attempt
    ProcessSpawn {
        command: String,
    },
    /// Environment variable access
    EnvAccess {
        variable: String,
    },
    /// System call attempt
    SystemCall {
        call: String,
    },
    /// CRITICAL: Extension doesn't match magic bytes
    ExtensionMismatch {
        claimed_ext: String,
        real_type: String,
        path: std::path::PathBuf,
    },
    /// Unknown file type encountered
    UnknownFileType {
        path: std::path::PathBuf,
        extension: String,
    },
    /// Extension mismatch detected during classification
    ClassificationMismatch {
        classification: ClassificationResult,
        path: std::path::PathBuf,
    },
}

/// Centralized intercept layer that evaluates all rules
/// and ensures audit logging on every verdict.
pub struct InterceptLayer {
    /// Security policy for evaluation
    pub policy: SecurityPolicy,
    /// Allowed write directories for the sandbox
    pub allowed_write_dirs: Vec<std::path::PathBuf>,
    /// Request ID for audit correlation
    pub request_id: uuid::Uuid,
}

impl InterceptLayer {
    /// Create a new intercept layer for a given request
    pub fn new(request_id: uuid::Uuid) -> Self {
        Self {
            policy: SecurityPolicy::new(SecurityMode::Mid),
            allowed_write_dirs: vec![std::path::PathBuf::from("/tmp/momo/workspace")],
            request_id,
        }
    }

    /// Create a new intercept layer with a specific security mode
    pub fn with_mode(request_id: uuid::Uuid, mode: SecurityMode) -> Self {
        Self {
            policy: SecurityPolicy::new(mode),
            allowed_write_dirs: vec![std::path::PathBuf::from("/tmp/momo/workspace")],
            request_id,
        }
    }

    /// Set the security mode
    pub fn set_mode(&mut self, mode: SecurityMode) {
        self.policy = SecurityPolicy::new(mode);
    }

    /// Evaluate any intercept event
    pub fn evaluate(&self, event: &InterceptEvent
    ) -> Verdict {
        let verdict = match event {
            InterceptEvent::FileRead { path, outside_workspace } => {
                self.evaluate_file_read(path, *outside_workspace)
            }
            InterceptEvent::FileWrite { path, outside_workspace } => {
                self.evaluate_file_write(path, *outside_workspace)
            }
            InterceptEvent::NetworkAccess { destination } => {
                self.evaluate_network(destination.as_deref())
            }
            InterceptEvent::ProcessSpawn { command } => {
                self.evaluate_process_spawn(command)
            }
            InterceptEvent::EnvAccess { variable } => {
                self.evaluate_env_access(variable)
            }
            InterceptEvent::SystemCall { call } => {
                self.evaluate_system_call(call)
            }
            InterceptEvent::ExtensionMismatch { claimed_ext, real_type, path } => {
                self.evaluate_extension_mismatch(claimed_ext, real_type, path)
            }
            InterceptEvent::UnknownFileType { path, extension } => {
                self.evaluate_unknown_file_type(path, extension)
            }
            InterceptEvent::ClassificationMismatch { classification, path } => {
                self.evaluate_classification_mismatch(classification, path)
            }
        };

        // Log blocked actions (GATE 7)
        self.log_if_blocked(event, &verdict);

        verdict
    }

    /// Evaluate a file read operation
    fn evaluate_file_read(
        &self,
        path: &std::path::Path,
        outside_workspace: bool,
    ) -> Verdict {
        match self.policy.evaluate_file_read(path, outside_workspace) {
            PolicyDecision::AutoAllow => Verdict::Allowed,
            PolicyDecision::AutoBlock { reason } => {
                Verdict::Blocked { reason }
            }
            PolicyDecision::Prompt { reason } => Verdict::Prompt { reason },
        }
    }

    /// Evaluate a file write operation
    fn evaluate_file_write(
        &self,
        path: &std::path::Path,
        outside_workspace: bool,
    ) -> Verdict {
        match self.policy.evaluate_file_write(path, outside_workspace) {
            PolicyDecision::AutoAllow => Verdict::Allowed,
            PolicyDecision::AutoBlock { reason } => {
                Verdict::Blocked { reason }
            }
            PolicyDecision::Prompt { reason } => Verdict::Prompt { reason },
        }
    }

    /// Evaluate a network access attempt
    fn evaluate_network(
        &self, destination: Option<&str>
    ) -> Verdict {
        match self.policy.evaluate_network(destination) {
            PolicyDecision::AutoAllow => Verdict::Allowed,
            PolicyDecision::AutoBlock { reason } => {
                Verdict::Blocked { reason }
            }
            PolicyDecision::Prompt { reason } => Verdict::Prompt { reason },
        }
    }

    /// Evaluate a process execution attempt
    fn evaluate_process_spawn(
        &self, _command: &str
    ) -> Verdict {
        match self.policy.evaluate_process_spawn() {
            PolicyDecision::AutoAllow => Verdict::Allowed,
            PolicyDecision::AutoBlock { reason } => {
                Verdict::Blocked { reason }
            }
            PolicyDecision::Prompt { reason } => Verdict::Prompt { reason },
        }
    }

    /// Evaluate environment variable access
    fn evaluate_env_access(&self, variable: &str
    ) -> Verdict {
        match self.policy.evaluate_env_access(variable) {
            PolicyDecision::AutoAllow => Verdict::Allowed,
            PolicyDecision::AutoBlock { reason } => {
                Verdict::Blocked { reason }
            }
            PolicyDecision::Prompt { reason } => Verdict::Prompt { reason },
        }
    }

    /// Evaluate a system call attempt
    fn evaluate_system_call(&self, call: &str
    ) -> Verdict {
        // Check for critical system calls
        let critical_syscalls = [
            "settimeofday",
            "clock_settime",
            "insmod",
            "modprobe",
            "rmmod",
            "kexec_load",
            "ptrace",
            "process_vm_writev",
        ];

        if critical_syscalls.contains(&call) {
            return Verdict::Blocked {
                reason: format!("Critical system call blocked: {}", call),
            };
        }

        Verdict::Allowed
    }

    /// Evaluate extension mismatch (CRITICAL event)
    fn evaluate_extension_mismatch(
        &self,
        claimed_ext: &str,
        real_type: &str,
        path: &std::path::Path,
    ) -> Verdict {
        let verdict = match self.policy.mode {
            SecurityMode::Hard => {
                // Auto-quarantine in HARD mode
                let reason = format!(
                    "CRITICAL: Extension mismatch in HARD mode. Claimed .{}, actual: {}",
                    claimed_ext, real_type
                );

                // Quarantine the file
                if let Ok(quarantine_path) = quarantine::quarantine_file(
                    path,
                    "EXTENSION_MISMATCH",
                    cage::Severity::Critical,
                    &self.request_id.to_string(),
                    &reason,
                    &format!("{:?}", self.policy.mode),
                    "AUTO_BLOCKED",
                ) {
                    Verdict::Quarantined {
                        path: quarantine_path,
                        reason,
                    }
                } else {
                    Verdict::Blocked { reason }
                }
            }
            _ => {
                // Prompt in other modes with strong warning
                Verdict::Prompt {
                    reason: format!(
                        "CRITICAL WARNING: File claims to be .{} but detected as {}. \
                         This may be a masquerade attack. Allow/Deny?",
                        claimed_ext, real_type
                    ),
                }
            }
        };

        // Log the extension mismatch event
        cage::log_intercept(
            cage::Severity::Critical,
            "EXTENSION_MISMATCH",
            &format!(
                "Extension mismatch: {} claims to be .{} but is actually {}",
                path.display(), claimed_ext, real_type
            ),
            self.request_id,
        );

        verdict
    }

    /// Evaluate unknown file type
    fn evaluate_unknown_file_type(
        &self,
        path: &std::path::Path,
        _extension: &str,
    ) -> Verdict {
        match self.policy.evaluate_unknown_file(&path.to_string_lossy()
        ) {
            PolicyDecision::AutoBlock { reason } => {
                Verdict::Blocked { reason }
            }
            PolicyDecision::Prompt { reason } => Verdict::Prompt { reason },
            PolicyDecision::AutoAllow => Verdict::Allowed,
        }
    }

    /// Evaluate classification mismatch
    fn evaluate_classification_mismatch(
        &self,
        classification: &ClassificationResult,
        path: &std::path::Path,
    ) -> Verdict {
        if !classification.extension_matches_magic {
            // Extension doesn't match magic detection
            return self.evaluate_extension_mismatch(
                &classification.claimed_extension,
                &format!("{:?}", classification.class),
                path,
            );
        }
        Verdict::Allowed
    }

    /// Log blocked actions (GATE 7 compliance)
    fn log_if_blocked(
        &self,
        event: &InterceptEvent,
        verdict: &Verdict,
    ) {
        match verdict {
            Verdict::Blocked { reason } => {
                let action = format!("{:?}", std::mem::discriminant(event));
                cage::log_intercept(
                    cage::Severity::High,
                    &action,
                    reason,
                    self.request_id,
                );
            }
            Verdict::Quarantined { reason, .. } => {
                let action = format!("{:?}", std::mem::discriminant(event));
                cage::log_intercept(
                    cage::Severity::Critical,
                    &action,
                    reason,
                    self.request_id,
                );
            }
            _ => {}
        }
    }

    /// Check if a path is within workspace
    pub fn is_outside_workspace(&self, path: &std::path::Path
    ) -> bool {
        !self.allowed_write_dirs.iter().any(|allowed| {
            path.starts_with(allowed)
        })
    }
}

/// File system intercept rules (legacy compatibility)
pub mod fs {
    use super::*;

    /// Sensitive path patterns that MUST be blocked
    const SENSITIVE_PATTERNS: &[&str] = &[
        "/.ssh/",
        "/.gnupg/",
        "/.env",
        "/secrets",
        "/credentials",
        "\\.ssh\\",
        "\\.gnupg\\",
        "\\.env",
    ];

    /// Check if a file read is permitted (legacy)
    pub fn allow_read(path: &std::path::Path) -> Verdict {
        let path_str = path.to_string_lossy();

        // Block reads from sensitive directories
        for pattern in SENSITIVE_PATTERNS {
            if path_str.contains(pattern) {
                return Verdict::Blocked {
                    reason: format!("Read from sensitive path blocked: {}", path_str),
                };
            }
        }

        // Block /proc/ and /sys/ access
        if path_str.starts_with("/proc/") || path_str.starts_with("/sys/") {
            return Verdict::Blocked {
                reason: format!("System path access blocked: {}", path_str),
            };
        }

        Verdict::Allowed
    }

    /// Check if a file write is permitted (legacy)
    pub fn allow_write(
        path: &std::path::Path,
        allowed_dirs: &[std::path::PathBuf],
    ) -> Verdict {
        for allowed in allowed_dirs {
            if path.starts_with(allowed) {
                return Verdict::Allowed;
            }
        }

        let path_str = path.to_string_lossy();
        Verdict::Blocked {
            reason: format!("Write outside allowed_paths blocked: {}", path_str),
        }
    }
}

/// Network intercept rules (legacy compatibility)
pub mod net {
    use super::*;

    /// BLOCK all outbound network calls
    ///
    /// GATE 4: No network calls outside MOMO-NETWORK-ALLOWED zones
    pub fn allow_network() -> Verdict {
        Verdict::Blocked {
            reason: "Network access blocked by cage policy".to_string(),
        }
    }
}

/// Process intercept rules (legacy compatibility)
pub mod process {
    use super::*;

    /// BLOCK all process spawning
    pub fn allow_exec() -> Verdict {
        Verdict::Blocked {
            reason: "Process execution blocked by cage policy".to_string(),
        }
    }

    /// BLOCK fork
    pub fn allow_fork() -> Verdict {
        Verdict::Blocked {
            reason: "Fork blocked by cage policy".to_string(),
        }
    }
}

/// System intercept rules (legacy compatibility)
pub mod system {
    use super::*;

    /// BLOCK system-level operations
    pub fn allow_system_call(call: &str) -> Verdict {
        match call {
            "settimeofday" | "clock_settime" => Verdict::Blocked {
                reason: "Clock manipulation blocked".to_string(),
            },
            "insmod" | "modprobe" | "rmmod" => Verdict::Blocked {
                reason: "Kernel module operation blocked".to_string(),
            },
            _ => Verdict::Allowed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_intercept_layer_with_mode() {
        let layer = InterceptLayer::with_mode(uuid::Uuid::new_v4(), SecurityMode::Hard);

        // In HARD mode, file reads should be blocked
        let event = InterceptEvent::FileRead {
            path: std::path::PathBuf::from("/tmp/test.txt"),
            outside_workspace: false,
        };

        let verdict = layer.evaluate(&event);
        assert!(matches!(verdict, Verdict::Blocked { .. }));
    }

    #[test]
    fn test_extension_mismatch_event() {
        let layer = InterceptLayer::with_mode(uuid::Uuid::new_v4(), SecurityMode::Mid);

        let event = InterceptEvent::ExtensionMismatch {
            claimed_ext: "txt".to_string(),
            real_type: "zip".to_string(),
            path: std::path::PathBuf::from("/tmp/fake.txt"),
        };

        let verdict = layer.evaluate(&event);
        // In MID mode, extension mismatch should prompt
        assert!(matches!(verdict, Verdict::Prompt { .. }));
    }

    #[test]
    fn test_unknown_file_type() {
        let layer = InterceptLayer::with_mode(uuid::Uuid::new_v4(), SecurityMode::Mid);

        let event = InterceptEvent::UnknownFileType {
            path: std::path::PathBuf::from("/tmp/mystery.xyz"),
            extension: "xyz".to_string(),
        };

        let verdict = layer.evaluate(&event);
        assert!(matches!(verdict, Verdict::Prompt { .. }));
    }

    #[test]
    fn test_critical_system_call_blocked() {
        let layer = InterceptLayer::with_mode(uuid::Uuid::new_v4(), SecurityMode::Easy);

        let event = InterceptEvent::SystemCall {
            call: "insmod".to_string(),
        };

        let verdict = layer.evaluate(&event);
        assert!(matches!(verdict, Verdict::Blocked { .. }));
    }

    #[test]
    fn test_network_blocked() {
        let layer = InterceptLayer::with_mode(uuid::Uuid::new_v4(), SecurityMode::Mid);

        let event = InterceptEvent::NetworkAccess {
            destination: Some("example.com".to_string()),
        };

        let verdict = layer.evaluate(&event);
        assert!(matches!(verdict, Verdict::Blocked { .. }));
    }

    #[test]
    fn test_process_spawn_blocked_mid_mode() {
        let layer = InterceptLayer::with_mode(uuid::Uuid::new_v4(), SecurityMode::Mid);

        let event = InterceptEvent::ProcessSpawn {
            command: "ls".to_string(),
        };

        let verdict = layer.evaluate(&event);
        assert!(matches!(verdict, Verdict::Blocked { .. }));
    }
}
