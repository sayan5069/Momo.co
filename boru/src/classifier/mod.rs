//! BORU Classifier — Universal file type detection
//!
//! HOTFIX 1: Detection is magic-bytes-first. Extensions are NEVER trusted.
//! detect_from_bytes() is the sole source of truth for file classification.

use anyhow::{Context, Result};
use std::path::Path;

pub mod magic;

/// Classification result with mismatch detection
#[derive(Debug, Clone)]
pub struct ClassificationResult {
    /// Detected file class (from magic bytes — the truth)
    pub class: magic::FileClass,
    /// File extension from path (the claim — may be a lie)
    pub claimed_extension: String,
    /// Whether extension matches magic bytes detection
    pub extension_matches_magic: bool,
    /// First 512 bytes of file (for heuristics)
    pub header_preview: Vec<u8>,
    /// File size in bytes
    pub file_size: u64,
    /// If mismatch: human-readable description of real type
    pub mismatch_detail: Option<String>,
}

/// File type classifier
pub struct FileClassifier;

impl FileClassifier {
    /// Create a new classifier
    pub fn new() -> Self {
        Self
    }

    /// Classify a file by path
    ///
    /// HOTFIX 1: Magic bytes are the SOLE source of truth.
    /// Extension is recorded but never used for classification.
    pub fn classify(&self, path: &Path) -> Result<ClassificationResult> {
        // Get extension claim (may be empty, may be a lie)
        let claimed_extension = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_string();

        // Read first 512 bytes for magic detection
        let header_preview = self.read_header(path)?;
        let file_size = std::fs::metadata(path)
            .with_context(|| format!("Failed to read metadata for {}", path.display()))?
            .len();

        // Detect from magic bytes — this is the ONLY trusted classification
        let detected_class = magic::detect_from_bytes(&header_preview);

        // Check for extension mismatch
        let mismatch = magic::check_extension_mismatch(path, &detected_class);
        let extension_matches_magic = mismatch.is_none();
        let mismatch_detail = mismatch.map(|(ext, real_desc)| {
            format!("File claims .{} but is actually: {}", ext, real_desc)
        });

        Ok(ClassificationResult {
            class: detected_class,
            claimed_extension,
            extension_matches_magic,
            header_preview,
            file_size,
            mismatch_detail,
        })
    }

    /// Read first 512 bytes of file for magic detection
    fn read_header(&self, path: &Path) -> Result<Vec<u8>> {
        use std::io::Read;

        let file = std::fs::File::open(path)
            .with_context(|| format!("Failed to open file: {}", path.display()))?;

        let mut buffer = vec![0u8; 512];
        let n = std::io::BufReader::new(file)
            .read(&mut buffer)
            .with_context(|| format!("Failed to read file header: {}", path.display()))?;

        buffer.truncate(n);
        Ok(buffer)
    }
}

impl Default for FileClassifier {
    fn default() -> Self {
        Self::new()
    }
}

/// Check if this is a potentially dangerous file type
pub fn is_dangerous_file(class: &magic::FileClass) -> bool {
    match class {
        magic::FileClass::Binary
        | magic::FileClass::JavaClass
        | magic::FileClass::Shell
        | magic::FileClass::Python
        | magic::FileClass::JavaScript
        | magic::FileClass::TypeScript
        | magic::FileClass::Ruby
        | magic::FileClass::Php
        | magic::FileClass::Perl
        | magic::FileClass::Lua
        | magic::FileClass::PowerShell => true,
        _ => false,
    }
}

/// Check if this file type can be executed
pub fn is_executable(class: &magic::FileClass) -> bool {
    matches!(
        class,
        magic::FileClass::Wasm
            | magic::FileClass::Binary
            | magic::FileClass::JavaClass
            | magic::FileClass::Python
            | magic::FileClass::JavaScript
            | magic::FileClass::TypeScript
            | magic::FileClass::Ruby
            | magic::FileClass::Php
            | magic::FileClass::Perl
            | magic::FileClass::Lua
            | magic::FileClass::Shell
            | magic::FileClass::PowerShell
            | magic::FileClass::R
            | magic::FileClass::Swift
            | magic::FileClass::Kotlin
            | magic::FileClass::Scala
    )
}

/// Get the appropriate runner for a file class
pub fn runner_for_class(class: &magic::FileClass) -> &'static str {
    match class {
        magic::FileClass::Wasm => "wasm",
        magic::FileClass::Binary | magic::FileClass::JavaClass => "binary",
        c if magic::is_interpreted(c) => "interpreter",
        c if magic::is_archive(c) => "archive",
        c if magic::is_static_document(c) => "scanner",
        _ => "heuristic",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_classify_wasm_file() {
        let temp_dir = std::env::temp_dir().join("boru_test");
        let _ = std::fs::create_dir_all(&temp_dir);
        let temp_file = temp_dir.join("test.wasm");

        {
            let mut file = std::fs::File::create(&temp_file).unwrap();
            file.write_all(b"\x00asm\x01\x00\x00\x00").unwrap();
        }

        let classifier = FileClassifier::new();
        let result = classifier.classify(&temp_file).unwrap();

        assert_eq!(result.class, magic::FileClass::Wasm);
        assert!(result.extension_matches_magic);
        assert_eq!(result.claimed_extension, "wasm");

        let _ = std::fs::remove_file(&temp_file);
    }

    #[test]
    fn test_extension_mismatch_detection() {
        // Create a file with .jpg extension but PNG magic bytes
        let temp_dir = std::env::temp_dir().join("boru_test");
        let _ = std::fs::create_dir_all(&temp_dir);
        let temp_file = temp_dir.join("fake_image.jpg");

        {
            let mut file = std::fs::File::create(&temp_file).unwrap();
            file.write_all(b"\x89PNG\r\n\x1a\n").unwrap();
        }

        let classifier = FileClassifier::new();
        let result = classifier.classify(&temp_file).unwrap();

        assert_eq!(result.class, magic::FileClass::Png);
        assert!(!result.extension_matches_magic);
        assert_eq!(result.claimed_extension, "jpg");

        let _ = std::fs::remove_file(&temp_file);
    }

    #[test]
    fn test_no_extension_file_classifies_without_crash() {
        let temp_dir = std::env::temp_dir().join("boru_test");
        let _ = std::fs::create_dir_all(&temp_dir);
        let temp_file = temp_dir.join("noextension");

        {
            let mut file = std::fs::File::create(&temp_file).unwrap();
            file.write_all(b"#!/usr/bin/env python3\nprint('hello')").unwrap();
        }

        let classifier = FileClassifier::new();
        let result = classifier.classify(&temp_file).unwrap();

        assert_eq!(result.class, magic::FileClass::Python);
        assert!(result.extension_matches_magic); // No ext = no mismatch
        assert_eq!(result.claimed_extension, "");

        let _ = std::fs::remove_file(&temp_file);
    }

    #[test]
    fn test_random_binary_disguised_as_pdf() {
        let temp_dir = std::env::temp_dir().join("boru_test");
        let _ = std::fs::create_dir_all(&temp_dir);
        let temp_file = temp_dir.join("fake_invoice.pdf");

        {
            let mut file = std::fs::File::create(&temp_file).unwrap();
            // Write ELF magic (not PDF)
            file.write_all(b"\x7fELF\x02\x01\x01\x00").unwrap();
        }

        let classifier = FileClassifier::new();
        let result = classifier.classify(&temp_file).unwrap();

        assert_eq!(result.class, magic::FileClass::Binary);
        assert!(!result.extension_matches_magic);
        assert!(result.mismatch_detail.is_some());

        let _ = std::fs::remove_file(&temp_file);
    }

    #[test]
    fn test_runner_selection() {
        assert_eq!(runner_for_class(&magic::FileClass::Wasm), "wasm");
        assert_eq!(runner_for_class(&magic::FileClass::Binary), "binary");
        assert_eq!(runner_for_class(&magic::FileClass::Python), "interpreter");
        assert_eq!(runner_for_class(&magic::FileClass::Zip), "archive");
        assert_eq!(runner_for_class(&magic::FileClass::Pdf), "scanner");
        assert_eq!(runner_for_class(&magic::FileClass::Unknown), "heuristic");
    }
}
