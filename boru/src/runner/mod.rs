//! BORU Runners — Execution strategies for different file types
//!
//! Execution strategies:
//! - WasmRunner: wasmtime sandbox (strongest isolation)
//! - InterpreterRunner: Bubblewrap + seccomp for interpreted languages
//! - BinaryRunner: seccomp + namespaces for native binaries
//! - ScannerRunner: Static analysis for documents/archives
//! - ArchiveRunner: Extract + recurse for archives
//! - HeuristicRunner: Magic byte matching for unknown files

use crate::classifier::magic::FileClass;
use crate::classifier::ClassificationResult;
use anyhow::Result;
use std::path::Path;

pub mod archive;
pub mod binary;
pub mod heuristic;
pub mod interpreter;
pub mod scanner;
pub mod wasm;

/// Execution verdict
#[derive(Debug, Clone)]
pub enum RunnerVerdict {
    /// Execution successful
    Success { output: String },
    /// Execution blocked
    Blocked { reason: String },
    /// Execution timed out (fuel exhausted)
    Timeout,
    /// Unsupported file type (no interpreter available)
    Unsupported { reason: String },
}

/// Runner trait — all runners implement this
pub trait Runner {
    /// Check if this runner can handle the given file class
    fn can_handle(&self, class: &FileClass) -> bool;

    /// Execute the file with the given runner
    ///
    /// Returns the verdict and any output
    fn execute(&self, path: &Path, classification: &ClassificationResult,
    ) -> Result<RunnerVerdict>;

    /// Check if required dependencies are available on the host
    fn check_dependencies(&self) -> Vec<DependencyStatus>;
}

/// Dependency status for interpreter detection
#[derive(Debug, Clone)]
pub struct DependencyStatus {
    /// Name of the dependency
    pub name: String,
    /// Whether it's available
    pub available: bool,
    /// Version string if available
    pub version: Option<String>,
    /// Host path if available
    pub path: Option<String>,
}

/// Router to select the appropriate runner
pub struct RunnerRouter {
    wasm: wasm::WasmRunner,
    interpreter: interpreter::InterpreterRunner,
    binary: binary::BinaryRunner,
    scanner: scanner::ScannerRunner,
    archive: archive::ArchiveRunner,
    heuristic: heuristic::HeuristicRunner,
}

impl RunnerRouter {
    /// Create a new runner router
    pub fn new() -> Self {
        Self {
            wasm: wasm::WasmRunner::new(),
            interpreter: interpreter::InterpreterRunner::new(),
            binary: binary::BinaryRunner::new(),
            scanner: scanner::ScannerRunner::new(),
            archive: archive::ArchiveRunner::new(),
            heuristic: heuristic::HeuristicRunner::new(),
        }
    }

    /// Route a file to the appropriate runner
    pub fn route(
        &self,
        path: &Path,
        classification: &ClassificationResult,
    ) -> Result<RunnerVerdict> {
        let class = &classification.class;

        use crate::classifier::magic::{is_interpreted, is_static_document, is_archive};

        // Select runner based on file class
        let runner: &dyn Runner = if class == &FileClass::Wasm {
            &self.wasm
        } else if class == &FileClass::Binary {
            &self.binary
        } else if is_interpreted(class) {
            &self.interpreter
        } else if is_static_document(class) {
            &self.scanner
        } else if is_archive(class) {
            &self.archive
        } else {
            &self.heuristic
        };

        runner.execute(path, classification)
    }

    /// Check all dependencies for all runners
    pub fn check_all_dependencies(&self) -> Vec<(&str, Vec<DependencyStatus>)> {
        vec![
            ("interpreter", self.interpreter.check_dependencies()),
            ("binary", self.binary.check_dependencies()),
        ]
    }
}

impl Default for RunnerRouter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_runner_verdict_variants() {
        let success = RunnerVerdict::Success {
            output: "test".to_string(),
        };
        assert!(matches!(success, RunnerVerdict::Success { .. }));

        let blocked = RunnerVerdict::Blocked {
            reason: "test".to_string(),
        };
        assert!(matches!(blocked, RunnerVerdict::Blocked { .. }));
    }
}
