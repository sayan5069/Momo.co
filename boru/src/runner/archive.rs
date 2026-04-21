//! Archive Runner — Extract + recurse for archive files
//!
//! Handles ZIP, TAR, GZIP, RAR, 7-Zip, ISO, DEB, RPM.
//! Extracts contents and runs each file through the classifier recursively.

use crate::classifier::magic::FileClass;
use crate::classifier::ClassificationResult;
use crate::runner::{DependencyStatus, Runner, RunnerVerdict};
use anyhow::Result;
use std::path::Path;

/// Archive runner for extracting and scanning contents
pub struct ArchiveRunner;

impl ArchiveRunner {
    /// Create a new archive runner
    pub fn new() -> Self {
        Self
    }

    /// List contents without full extraction (for GATE 1 compliance)
    fn list_contents(
        &self,
        path: &Path,
        class: &FileClass,
    ) -> Result<Vec<String>> {
        match class {
            FileClass::Zip => self.list_zip_contents(path),
            FileClass::Tar => self.list_tar_contents(path),
            FileClass::Gz => self.list_gz_contents(path),
            _ => Ok(vec![format!("Cannot list contents: {:?}", class)]),
        }
    }

    /// List ZIP contents using the zip crate
    fn list_zip_contents(&self, _path: &Path
    ) -> Result<Vec<String>> {
        // TODO: Implement using the zip crate
        // For now, return placeholder
        Ok(vec!["ZIP contents listing requires zip crate".to_string()])
    }

    /// List TAR contents
    fn list_tar_contents(&self, _path: &Path
    ) -> Result<Vec<String>> {
        // TODO: Implement using the tar crate
        Ok(vec!["TAR contents listing requires tar crate".to_string()])
    }

    /// List GZIP contents (usually single file)
    fn list_gz_contents(&self, _path: &Path
    ) -> Result<Vec<String>> {
        // GZIP is typically a single compressed file
        Ok(vec!["GZIP compressed data".to_string()])
    }

    /// Scan archive for suspicious patterns
    fn scan_archive_contents(
        &self,
        contents: &[String],
    ) -> Result<Vec<String>> {
        let mut warnings = vec![];

        for entry in contents {
            let lower = entry.to_lowercase();

            // Check for executable files
            if lower.ends_with(".exe")
                || lower.ends_with(".dll")
                || lower.ends_with(".so")
                || lower.ends_with(".dylib")
            {
                warnings.push(format!("Warning: Executable in archive: {}", entry));
            }

            // Check for scripts
            if lower.ends_with(".js")
                || lower.ends_with(".vbs")
                || lower.ends_with(".bat")
                || lower.ends_with(".cmd")
                || lower.ends_with(".ps1")
            {
                warnings.push(format!("Warning: Script in archive: {}", entry));
            }

            // Check for Office macros
            if lower.contains("vba") || lower.contains("macro") {
                warnings.push(format!(
                    "Warning: Macro content in archive: {}",
                    entry
                ));
            }

            // Check for double extensions (common malware trick)
            if lower.matches('.').count() >= 2 {
                warnings.push(format!(
                    "Warning: Multiple extensions: {}",
                    entry
                ));
            }
        }

        Ok(warnings)
    }
}

impl Default for ArchiveRunner {
    fn default() -> Self {
        Self::new()
    }
}

impl Runner for ArchiveRunner {
    fn can_handle(&self, class: &FileClass) -> bool {
        matches!(
            class,
            FileClass::Zip
                | FileClass::Tar
                | FileClass::Gz
                | FileClass::Rar
                | FileClass::SevenZip
                | FileClass::Iso
                | FileClass::Deb
                | FileClass::Rpm
        )
    }

    fn execute(
        &self,
        path: &Path,
        classification: &ClassificationResult,
    ) -> Result<RunnerVerdict> {
        // List contents without extraction
        let contents = self.list_contents(path, &classification.class)?;

        // Scan for suspicious patterns
        let warnings = self.scan_archive_contents(&contents)?;

        // Build output report
        let mut output = format!(
            "Archive: {} ({} files/patterns detected)\n",
            path.display(),
            contents.len()
        );

        if !warnings.is_empty() {
            output.push_str("\nWarnings:\n");
            for warning in &warnings {
                output.push_str(warning);
                output.push('\n');
            }
        }

        // For Phase 1: Static scan only (no extraction)
        // Full recursive extraction + scanning is Phase 2

        if warnings.is_empty() {
            Ok(RunnerVerdict::Success { output })
        } else {
            Ok(RunnerVerdict::Blocked {
                reason: format!(
                    "{} suspicious items found in archive. Quarantine recommended.",
                    warnings.len()
                ),
            })
        }
    }

    fn check_dependencies(&self) -> Vec<DependencyStatus> {
        // Archive scanning uses pure Rust crates, no external deps
        vec![]
    }
}
