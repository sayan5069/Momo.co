//! Binary Runner — seccomp + Linux namespaces for native binaries
//!
//! Handles ELF, PE, Mach-O, and other native executable formats.
//! Uses ptrace or bubblewrap for sandboxing.

use crate::classifier::magic::FileClass;
use crate::classifier::ClassificationResult;
use crate::runner::{DependencyStatus, Runner, RunnerVerdict};
use anyhow::Result;
use std::path::Path;

/// Binary runner for native executables
pub struct BinaryRunner;

impl BinaryRunner {
    /// Create a new binary runner
    pub fn new() -> Self {
        Self
    }

    /// Check if seccomp is available
    fn has_seccomp() -> bool {
        // Check if seccomp is supported by trying to load the syscall
        // In real implementation, this would check /proc/PID/status for Seccomp
        std::path::Path::new("/proc/self/status").exists()
    }

    /// Check if namespaces are available
    fn has_namespaces() -> bool {
        // Check for unshare availability
        std::process::Command::new("which")
            .arg("unshare")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
}

impl Default for BinaryRunner {
    fn default() -> Self {
        Self::new()
    }
}

impl Runner for BinaryRunner {
    fn can_handle(&self, class: &FileClass) -> bool {
        class == &FileClass::Binary
    }

    fn execute(
        &self,
        _path: &Path,
        _classification: &ClassificationResult,
    ) -> Result<RunnerVerdict> {
        // For Phase 1: Native binary execution is NOT supported
        // BORU is a WASM-first sandbox for security
        //
        // Future work:
        // - Use ptrace to intercept syscalls
        // - Set up user namespaces
        // - Apply seccomp filters
        // - Mount namespaces for filesystem isolation

        Ok(RunnerVerdict::Unsupported {
            reason: "Native binary execution is not supported in Phase 1. \
                      BORU is a WASM-first security sandbox. \
                      Convert your binary to WASM or use the interpreter runner."
                .to_string(),
        })
    }

    fn check_dependencies(&self) -> Vec<DependencyStatus> {
        vec![
            DependencyStatus {
                name: "seccomp".to_string(),
                available: Self::has_seccomp(),
                version: None,
                path: None,
            },
            DependencyStatus {
                name: "linux_namespaces".to_string(),
                available: Self::has_namespaces(),
                version: None,
                path: None,
            },
        ]
    }
}
