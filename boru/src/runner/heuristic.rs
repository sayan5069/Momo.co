//! Heuristic Runner — Magic byte matching for unknown files
//!
//! For files with unknown extensions or no magic bytes match,
//! applies heuristic analysis to determine the best runner.

use crate::classifier::magic::FileClass;
use crate::classifier::ClassificationResult;
use crate::runner::{DependencyStatus, Runner, RunnerVerdict};
use anyhow::Result;
use std::path::Path;

/// Heuristic runner for unknown file types
pub struct HeuristicRunner;

impl HeuristicRunner {
    /// Create a new heuristic runner
    pub fn new() -> Self {
        Self
    }

    /// Analyze file content for hints
    fn analyze_content(&self, _data: &[u8]
    ) -> ContentAnalysis {
        // Content analysis heuristics:
        // 1. Check for shebang (#!) patterns
        // 2. Look for common script signatures
        // 3. Check for binary vs text
        // 4. Look for encoded data (base64, hex)

        ContentAnalysis {
            has_shebang: false,
            is_text: false,
            is_binary: false,
            confidence: 0.0,
            suggested_class: FileClass::Unknown,
        }
    }

    /// Check for shebang and return interpreter
    fn detect_shebang(&self,
        data: &[u8]
    ) -> Option<&'static str> {
        if data.starts_with(b"#!/") {
            // Parse shebang line
            let shebang = String::from_utf8_lossy(data);
            let line = shebang.lines().next()?;

            if line.contains("python") {
                Some("python")
            } else if line.contains("node") || line.contains("nodejs") {
                Some("node")
            } else if line.contains("bash") || line.contains("sh") {
                Some("bash")
            } else if line.contains("ruby") {
                Some("ruby")
            } else if line.contains("perl") {
                Some("perl")
            } else {
                Some("unknown_interpreter")
            }
        } else {
            None
        }
    }

    /// Check if data is likely text
    fn is_likely_text(&self, data: &[u8]
    ) -> bool {
        // Simple heuristic: check for high proportion of printable ASCII
        if data.is_empty() {
            return false;
        }

        let printable_count = data
            .iter()
            .filter(|&&b| b.is_ascii_graphic() || b.is_ascii_whitespace())
            .count();

        let ratio = printable_count as f64 / data.len() as f64;
        ratio > 0.8
    }

    /// Generate recommendation for unknown file
    fn recommend_action(&self, _path: &Path, data: &[u8]) -> String {
        let mut recommendations = vec![];

        // Check for shebang
        if let Some(interp) = self.detect_shebang(data) {
            recommendations.push(format!(
                "Detected shebang: {} interpreter",
                interp
            ));
        }

        // Check if text or binary
        if self.is_likely_text(data) {
            recommendations.push("File appears to be text".to_string());

            // Look for script patterns
            let text = String::from_utf8_lossy(data);
            if text.contains("function") || text.contains("var ") || text.contains("const ")
            {
                recommendations.push("Contains JavaScript-like patterns".to_string());
            }
            if text.contains("def ") || text.contains("import ") {
                recommendations.push("Contains Python-like patterns".to_string());
            }
        } else {
            recommendations.push("File appears to be binary data".to_string());
        }

        if recommendations.is_empty() {
            "No heuristics matched. Treat as unsafe.".to_string()
        } else {
            recommendations.join("\n")
        }
    }
}

impl Default for HeuristicRunner {
    fn default() -> Self {
        Self::new()
    }
}

impl Runner for HeuristicRunner {
    fn can_handle(&self, class: &FileClass) -> bool {
        class == &FileClass::Unknown
    }

    fn execute(
        &self,
        path: &Path,
        _classification: &ClassificationResult,
    ) -> Result<RunnerVerdict> {
        // Read first 4KB for heuristic analysis
        let data = std::fs::read(path)?;
        let preview = if data.len() > 4096 {
            &data[..4096]
        } else {
            &data[..]
        };

        let recommendation = self.recommend_action(path, preview);

        // For unknown files, we don't execute — we return analysis
        Ok(RunnerVerdict::Blocked {
            reason: format!(
                "Unknown file type. Heuristic analysis:\n{}\n\n\
                 This file cannot be executed safely. Consider:\n\
                 1. Verifying the file source\n\
                 2. Converting to a supported format\n\
                 3. Using a specific runner with explicit file type",
                recommendation
            ),
        })
    }

    fn check_dependencies(&self) -> Vec<DependencyStatus> {
        // No external dependencies
        vec![]
    }
}

/// Content analysis result
struct ContentAnalysis {
    /// Has shebang line
    has_shebang: bool,
    /// Appears to be text
    is_text: bool,
    /// Appears to be binary
    is_binary: bool,
    /// Confidence level (0.0 - 1.0)
    confidence: f64,
    /// Suggested file class
    suggested_class: FileClass,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_shebang_python() {
        let runner = HeuristicRunner::new();
        let data = b"#!/usr/bin/env python3\nprint('hello')";
        assert_eq!(runner.detect_shebang(data), Some("python"));
    }

    #[test]
    fn test_detect_shebang_bash() {
        let runner = HeuristicRunner::new();
        let data = b"#!/bin/bash\necho hello";
        assert_eq!(runner.detect_shebang(data), Some("bash"));
    }

    #[test]
    fn test_is_likely_text() {
        let runner = HeuristicRunner::new();
        assert!(runner.is_likely_text(b"hello world\nthis is text"));
        assert!(!runner.is_likely_text(b"\x00\x01\x02\x03\xff\xfe"));
    }

    #[test]
    fn test_no_shebang() {
        let runner = HeuristicRunner::new();
        let data = b"just some text";
        assert_eq!(runner.detect_shebang(data), None);
    }
}
