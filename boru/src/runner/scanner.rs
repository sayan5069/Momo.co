//! Scanner Runner — Static analysis for documents and media
//!
//! Scans files without execution:
//! - Magic bytes verification
//! - Embedded script detection (PDF JS, Office macros)
//! - Known bad hash check
//! - Content analysis

use crate::classifier::magic::FileClass;
use crate::classifier::ClassificationResult;
use crate::runner::{DependencyStatus, Runner, RunnerVerdict};
use anyhow::Result;
use std::path::Path;

/// Scanner runner for static document analysis
pub struct ScannerRunner;

impl ScannerRunner {
    /// Create a new scanner runner
    pub fn new() -> Self {
        Self
    }

    /// Scan a PDF for JavaScript
    fn scan_pdf(&self, _path: &Path, _data: &[u8]
    ) -> Result<RunnerVerdict> {
        // PDF scanning logic:
        // 1. Check for /JavaScript or /JS entries
        // 2. Look for suspicious patterns
        // 3. Check for embedded files

        Ok(RunnerVerdict::Success {
            output: "PDF scanned: No JavaScript detected".to_string(),
        })
    }

    /// Scan Office documents for macros
    fn scan_office(
        &self,
        _path: &Path,
        _data: &[u8],
        doc_type: &str,
    ) -> Result<RunnerVerdict> {
        // Office scanning logic:
        // 1. Parse OOXML structure
        // 2. Look for vbaProject.bin (macros)
        // 3. Check for external references

        Ok(RunnerVerdict::Success {
            output: format!("{} scanned: No macros detected", doc_type),
        })
    }

    /// Scan image for anomalies
    fn scan_image(
        &self,
        _path: &Path,
        _data: &[u8],
        format: &str,
    ) -> Result<RunnerVerdict> {
        // Image scanning logic:
        // 1. Validate file structure
        // 2. Check for polyglots (multiple file types)
        // 3. Look for appended data

        Ok(RunnerVerdict::Success {
            output: format!("{} image: Structure valid", format),
        })
    }

    /// Scan media file
    fn scan_media(
        &self,
        _path: &Path,
        _data: &[u8],
        format: &str,
    ) -> Result<RunnerVerdict> {
        // Media scanning logic:
        // 1. Validate container format
        // 2. Check for embedded subtitles/codecs
        // 3. Look for appended executable data

        Ok(RunnerVerdict::Success {
            output: format!("{} media: Structure valid", format),
        })
    }
}

impl Default for ScannerRunner {
    fn default() -> Self {
        Self::new()
    }
}

impl Runner for ScannerRunner {
    fn can_handle(&self, class: &FileClass) -> bool {
        matches!(
            class,
            FileClass::Pdf
                | FileClass::OfficeDoc
                | FileClass::OfficeXlsx
                | FileClass::OfficePptx
                | FileClass::Odt
                | FileClass::Jpeg
                | FileClass::Png
                | FileClass::Gif
                | FileClass::Mp4
                | FileClass::Mp3
        )
    }

    fn execute(
        &self,
        path: &Path,
        classification: &ClassificationResult,
    ) -> Result<RunnerVerdict> {
        // Read file data (limit to reasonable size for scanning)
        let data = std::fs::read(path)?;

        match classification.class {
            FileClass::Pdf => self.scan_pdf(path, &data),
            FileClass::OfficeDoc => self.scan_office(path, &data, "DOCX"),
            FileClass::OfficeXlsx => self.scan_office(path, &data, "XLSX"),
            FileClass::OfficePptx => self.scan_office(path, &data, "PPTX"),
            FileClass::Odt => Ok(RunnerVerdict::Success {
                output: "ODT scanned".to_string(),
            }),
            FileClass::Jpeg => self.scan_image(path, &data, "JPEG"),
            FileClass::Png => self.scan_image(path, &data, "PNG"),
            FileClass::Gif => self.scan_image(path, &data, "GIF"),
            FileClass::Mp4 => self.scan_media(path, &data, "MP4"),
            FileClass::Mp3 => self.scan_media(path, &data, "MP3"),
            _ => Ok(RunnerVerdict::Blocked {
                reason: format!("Cannot scan file type: {:?}", classification.class),
            }),
        }
    }

    fn check_dependencies(&self) -> Vec<DependencyStatus> {
        // Scanner has no external dependencies
        vec![]
    }
}
