//! BORU Classifier — Universal file type detection
//!
//! Detects file types using two-layer approach:
//! 1. Extension hint
//! 2. Magic bytes verification (extension lying = CRITICAL event)

use anyhow::{Context, Result};
use std::path::Path;

pub mod magic;

/// Classification result with mismatch detection
#[derive(Debug, Clone)]
pub struct ClassificationResult {
    /// Detected file class
    pub class: magic::FileClass,
    /// File extension from path
    pub claimed_extension: String,
    /// Whether extension matches magic bytes detection
    pub extension_matches_magic: bool,
    /// First 512 bytes of file (for heuristics)
    pub header_preview: Vec<u8>,
    /// File size in bytes
    pub file_size: u64,
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
    /// Returns the classification result, checking for extension/magic mismatch
    pub fn classify(&self, path: &Path) -> Result<ClassificationResult> {
        // Get extension hint
        let claimed_extension = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_string();

        // Get expected class from extension
        let claimed_class = magic::class_from_extension(&claimed_extension);

        // Read first 512 bytes for magic detection
        let header_preview = self.read_header(path)?;
        let file_size = std::fs::metadata(path)
            .with_context(|| format!("Failed to read metadata for {}", path.display()))?
            .len();

        // Detect from magic bytes
        let magic_class = magic::class_from_magic_bytes(&header_preview)
            .unwrap_or(magic::FileClass::Unknown);

        // Determine if there's a mismatch
        // Note: ZIP-based formats (docx, xlsx) will be detected as ZIP by magic
        let extension_matches_magic = if magic_class == magic::FileClass::Zip {
            matches!(
                claimed_class,
                magic::FileClass::Zip
                    | magic::FileClass::OfficeDoc
                    | magic::FileClass::OfficeXlsx
                    | magic::FileClass::OfficePptx
            )
        } else if magic_class == magic::FileClass::Unknown {
            // No magic detection, trust extension for interpreted languages
            claimed_class != magic::FileClass::Unknown
        } else {
            claimed_class == magic_class
        };

        // Final class: prefer magic detection, fall back to extension
        let class = if magic_class != magic::FileClass::Unknown {
            magic_class
        } else {
            claimed_class
        };

        Ok(ClassificationResult {
            class,
            claimed_extension,
            extension_matches_magic,
            header_preview,
            file_size,
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
        magic::FileClass::Binary => "binary",
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
        // Create temp WASM file
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
        // Create a file with .txt extension but PNG magic
        let temp_dir = std::env::temp_dir().join("boru_test");
        let _ = std::fs::create_dir_all(&temp_dir);
        let temp_file = temp_dir.join("fake_text.txt");

        {
            let mut file = std::fs::File::create(&temp_file).unwrap();
            file.write_all(b"\x89PNG\r\n\x1a\n").unwrap();
        }

        let classifier = FileClassifier::new();
        let result = classifier.classify(&temp_file).unwrap();

        assert_eq!(result.class, magic::FileClass::Png);
        assert!(!result.extension_matches_magic);
        assert_eq!(result.claimed_extension, "txt");

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
