//! Magic Bytes Database — File type detection via magic bytes
//!
//! HOTFIX 1: This module physically reads file bytes for detection.
//! Extension strings are NEVER trusted for classification.
//! Shebang lines are detected for interpreted scripts.

use std::path::Path;

/// File class categories
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileClass {
    // Executable categories
    Wasm,
    Binary,
    JavaClass,
    // Interpreted languages
    Python,
    JavaScript,
    TypeScript,
    Ruby,
    Php,
    Perl,
    Lua,
    Shell,
    PowerShell,
    R,
    Swift,
    Kotlin,
    Scala,
    // Static documents
    Pdf,
    OfficeDoc,
    OfficeXlsx,
    OfficePptx,
    Odt,
    // Images
    Jpeg,
    Png,
    Gif,
    // Media
    Mp4,
    Mp3,
    // Archives
    Zip,
    Tar,
    Gz,
    Rar,
    SevenZip,
    Iso,
    Deb,
    Rpm,
    // Unknown
    Unknown,
}

/// Magic bytes entry for file detection
#[derive(Debug)]
pub struct MagicEntry {
    /// Magic bytes to match
    pub bytes: &'static [u8],
    /// Offset where magic bytes appear (usually 0)
    pub offset: usize,
    /// File class this indicates
    pub class: FileClass,
    /// Human-readable description
    pub description: &'static str,
}

/// Magic bytes database for file type detection
pub static MAGIC_DATABASE: &[MagicEntry] = &[
    // WASM - WebAssembly
    MagicEntry {
        bytes: b"\x00asm",
        offset: 0,
        class: FileClass::Wasm,
        description: "WebAssembly module",
    },
    // ELF - Linux native binaries
    MagicEntry {
        bytes: b"\x7fELF",
        offset: 0,
        class: FileClass::Binary,
        description: "ELF executable",
    },
    // Mach-O (32-bit)
    MagicEntry {
        bytes: b"\xfe\xed\xfa\xce",
        offset: 0,
        class: FileClass::Binary,
        description: "Mach-O 32-bit",
    },
    // Mach-O (64-bit)
    MagicEntry {
        bytes: b"\xfe\xed\xfa\xcf",
        offset: 0,
        class: FileClass::Binary,
        description: "Mach-O 64-bit",
    },
    // PE/COFF - Windows executables
    MagicEntry {
        bytes: b"MZ",
        offset: 0,
        class: FileClass::Binary,
        description: "PE executable",
    },
    // Java class file (must come BEFORE Mach-O fat binary — same bytes 0xCAFEBABE)
    MagicEntry {
        bytes: b"\xCA\xFE\xBA\xBE",
        offset: 0,
        class: FileClass::JavaClass,
        description: "Java class file / Mach-O fat binary",
    },
    // PDF documents
    MagicEntry {
        bytes: b"%PDF-",
        offset: 0,
        class: FileClass::Pdf,
        description: "PDF document",
    },
    // ZIP format (also DOCX, XLSX, PPTX, JAR)
    MagicEntry {
        bytes: b"PK\x03\x04",
        offset: 0,
        class: FileClass::Zip,
        description: "ZIP archive",
    },
    MagicEntry {
        bytes: b"PK\x05\x06",
        offset: 0,
        class: FileClass::Zip,
        description: "ZIP archive (empty)",
    },
    MagicEntry {
        bytes: b"PK\x07\x08",
        offset: 0,
        class: FileClass::Zip,
        description: "ZIP archive (spanned)",
    },
    // GZIP
    MagicEntry {
        bytes: b"\x1f\x8b",
        offset: 0,
        class: FileClass::Gz,
        description: "GZIP compressed",
    },
    // TAR (ustar)
    MagicEntry {
        bytes: b"ustar",
        offset: 257,
        class: FileClass::Tar,
        description: "TAR archive",
    },
    // RAR v4
    MagicEntry {
        bytes: b"Rar!\x1a\x07\x00",
        offset: 0,
        class: FileClass::Rar,
        description: "RAR archive v4",
    },
    // RAR v5
    MagicEntry {
        bytes: b"Rar!\x1a\x07\x01\x00",
        offset: 0,
        class: FileClass::Rar,
        description: "RAR archive v5",
    },
    // 7-Zip
    MagicEntry {
        bytes: b"7z\xbc\xaf\x27\x1c",
        offset: 0,
        class: FileClass::SevenZip,
        description: "7-Zip archive",
    },
    // JPEG
    MagicEntry {
        bytes: b"\xff\xd8\xff",
        offset: 0,
        class: FileClass::Jpeg,
        description: "JPEG image",
    },
    // PNG
    MagicEntry {
        bytes: b"\x89PNG\r\n\x1a\n",
        offset: 0,
        class: FileClass::Png,
        description: "PNG image",
    },
    // GIF87a
    MagicEntry {
        bytes: b"GIF87a",
        offset: 0,
        class: FileClass::Gif,
        description: "GIF image (87a)",
    },
    // GIF89a
    MagicEntry {
        bytes: b"GIF89a",
        offset: 0,
        class: FileClass::Gif,
        description: "GIF image (89a)",
    },
    // MP4 (ftyp box)
    MagicEntry {
        bytes: b"ftyp",
        offset: 4,
        class: FileClass::Mp4,
        description: "MP4 video",
    },
    // MP3 with ID3v2
    MagicEntry {
        bytes: b"ID3",
        offset: 0,
        class: FileClass::Mp3,
        description: "MP3 audio (ID3)",
    },
    // ISO 9660
    MagicEntry {
        bytes: b"CD001",
        offset: 32769,
        class: FileClass::Iso,
        description: "ISO 9660 image",
    },
    // Debian package
    MagicEntry {
        bytes: b"!<arch>\ndebian-binary",
        offset: 0,
        class: FileClass::Deb,
        description: "Debian package",
    },
    // RPM package
    MagicEntry {
        bytes: b"\xed\xab\xee\xdb",
        offset: 0,
        class: FileClass::Rpm,
        description: "RPM package",
    },
];

/// Detect file class from raw bytes (first 512 bytes).
///
/// This is the ONLY trusted detection path. Extensions are NOT used here.
/// Steps:
///   1. Check magic byte signatures from MAGIC_DATABASE
///   2. Check MP3 sync word (0xFF 0xFB/0xF3/0xF2)
///   3. Check shebang lines for interpreted scripts
///   4. If nothing matches → FileClass::Unknown
pub fn detect_from_bytes(bytes: &[u8]) -> FileClass {
    if bytes.is_empty() {
        return FileClass::Unknown;
    }

    // Step 1: Check magic byte database
    for entry in MAGIC_DATABASE {
        let end = entry.offset + entry.bytes.len();
        if bytes.len() >= end && &bytes[entry.offset..end] == entry.bytes {
            return entry.class.clone();
        }
    }

    // Step 2: MP3 sync word (0xFF followed by 0xFB, 0xF3, or 0xF2)
    if bytes.len() >= 2 && bytes[0] == 0xFF && (bytes[1] == 0xFB || bytes[1] == 0xF3 || bytes[1] == 0xF2) {
        return FileClass::Mp3;
    }

    // Step 3: Shebang detection for interpreted scripts
    if bytes.len() >= 2 && &bytes[0..2] == b"#!" {
        return detect_shebang(bytes);
    }

    // Step 4: No match
    FileClass::Unknown
}

/// Detect script type from shebang line
fn detect_shebang(bytes: &[u8]) -> FileClass {
    // Extract the first line (up to newline or 256 bytes, whichever comes first)
    let end = bytes.iter().position(|&b| b == b'\n').unwrap_or(bytes.len().min(256));
    let shebang_line = match std::str::from_utf8(&bytes[..end]) {
        Ok(s) => s,
        Err(_) => return FileClass::Unknown,
    };

    // Python
    if shebang_line.contains("python") {
        return FileClass::Python;
    }
    // Node.js (must check before generic "sh" to avoid false match on "#!/usr/bin/env node")
    if shebang_line.contains("node") {
        return FileClass::JavaScript;
    }
    // Ruby
    if shebang_line.contains("ruby") {
        return FileClass::Ruby;
    }
    // Perl
    if shebang_line.contains("perl") {
        return FileClass::Perl;
    }
    // PHP
    if shebang_line.contains("php") {
        return FileClass::Php;
    }
    // Lua
    if shebang_line.contains("lua") {
        return FileClass::Lua;
    }
    // R
    if shebang_line.contains("Rscript") {
        return FileClass::R;
    }
    // Shell (bash, sh, zsh, fish, dash — check last to avoid false positives)
    if shebang_line.contains("/bin/bash")
        || shebang_line.contains("/bin/sh")
        || shebang_line.contains("/bin/zsh")
        || shebang_line.contains("/bin/fish")
        || shebang_line.contains("/bin/dash")
        || shebang_line.contains("env bash")
        || shebang_line.contains("env sh")
        || shebang_line.contains("env zsh")
    {
        return FileClass::Shell;
    }

    // Unknown shebang — still a script of some kind, treat as Shell
    FileClass::Shell
}

/// Check for extension mismatch between claimed extension and detected FileClass.
///
/// Returns Some((claimed_ext, real_type_description)) if mismatch detected.
/// Returns None if no mismatch, or if the file has no extension.
///
/// Files with no extension skip this check entirely (no crash).
pub fn check_extension_mismatch(path: &Path, detected: &FileClass) -> Option<(String, String)> {
    // No extension → skip check entirely. Do not crash.
    let ext = match path.extension().and_then(|e| e.to_str()) {
        Some(e) => e.to_lowercase(),
        None => return None,
    };

    // If detection was Unknown but the extension claims a format with known magic bytes,
    // that IS a mismatch. A real PDF would start with %PDF-, a real PNG with \x89PNG, etc.
    // Only skip if the extension itself maps to Unknown or an interpreted language
    // (scripts don't have magic bytes unless they have a shebang).
    if *detected == FileClass::Unknown {
        let expected = class_from_extension(&ext);
        if expected == FileClass::Unknown || is_interpreted(&expected) {
            return None;
        }
        // Extension claims a format with identifiable magic bytes, but none matched.
        // This is suspicious — flag it.
        return Some((
            ext,
            format!("Unknown (no {} magic bytes found)", class_description(&expected)),
        ));
    }

    let expected = class_from_extension(&ext);

    // If extension maps to Unknown, we can't compare
    if expected == FileClass::Unknown {
        return None;
    }

    // Special case: ZIP-based Office formats (docx/xlsx/pptx are ZIP by magic)
    if *detected == FileClass::Zip {
        if matches!(expected, FileClass::OfficeDoc | FileClass::OfficeXlsx | FileClass::OfficePptx | FileClass::Zip) {
            return None; // Not a mismatch
        }
    }

    // Special case: JavaClass and Binary share 0xCAFEBABE (Mach-O fat binary)
    if (*detected == FileClass::JavaClass && expected == FileClass::Binary)
        || (*detected == FileClass::Binary && expected == FileClass::JavaClass)
    {
        return None;
    }

    // Compare
    if expected != *detected {
        Some((
            ext,
            class_description(detected).to_string(),
        ))
    } else {
        None
    }
}

/// Legacy wrapper — kept for backward compatibility
pub fn class_from_magic_bytes(data: &[u8]) -> Option<FileClass> {
    let class = detect_from_bytes(data);
    if class == FileClass::Unknown {
        None
    } else {
        Some(class)
    }
}

/// Extension to file class mapping
pub fn class_from_extension(ext: &str) -> FileClass {
    match ext.to_lowercase().as_str() {
        "wasm" => FileClass::Wasm,
        "exe" | "dll" | "scr" | "msi" | "bin" | "out" | "elf" | "so" | "appimage" | "dylib" | "app" | "dmg" => FileClass::Binary,
        "class" => FileClass::JavaClass,
        "py" => FileClass::Python,
        "js" => FileClass::JavaScript,
        "ts" => FileClass::TypeScript,
        "rb" => FileClass::Ruby,
        "php" => FileClass::Php,
        "pl" | "pm" => FileClass::Perl,
        "lua" => FileClass::Lua,
        "sh" | "bash" | "zsh" | "fish" => FileClass::Shell,
        "ps1" => FileClass::PowerShell,
        "bat" | "cmd" => FileClass::Shell,
        "r" => FileClass::R,
        "swift" => FileClass::Swift,
        "kt" | "kts" => FileClass::Kotlin,
        "scala" | "sc" => FileClass::Scala,
        "pdf" => FileClass::Pdf,
        "docx" => FileClass::OfficeDoc,
        "xlsx" => FileClass::OfficeXlsx,
        "pptx" => FileClass::OfficePptx,
        "odt" | "ods" | "odp" => FileClass::Odt,
        "jpg" | "jpeg" => FileClass::Jpeg,
        "png" => FileClass::Png,
        "gif" => FileClass::Gif,
        "mp4" | "mov" | "avi" | "mkv" => FileClass::Mp4,
        "mp3" | "wav" | "flac" | "aac" => FileClass::Mp3,
        "zip" | "jar" | "war" => FileClass::Zip,
        "tar" => FileClass::Tar,
        "gz" | "tgz" | "bz2" | "xz" => FileClass::Gz,
        "rar" => FileClass::Rar,
        "7z" => FileClass::SevenZip,
        "iso" => FileClass::Iso,
        "deb" => FileClass::Deb,
        "rpm" => FileClass::Rpm,
        _ => FileClass::Unknown,
    }
}

/// Get human-readable description for a file class
pub fn class_description(class: &FileClass) -> &'static str {
    match class {
        FileClass::Wasm => "WebAssembly module",
        FileClass::Binary => "Native binary executable",
        FileClass::JavaClass => "Java class file",
        FileClass::Python => "Python script",
        FileClass::JavaScript => "JavaScript",
        FileClass::TypeScript => "TypeScript",
        FileClass::Ruby => "Ruby script",
        FileClass::Php => "PHP script",
        FileClass::Perl => "Perl script",
        FileClass::Lua => "Lua script",
        FileClass::Shell => "Shell script",
        FileClass::PowerShell => "PowerShell script",
        FileClass::R => "R script",
        FileClass::Swift => "Swift script",
        FileClass::Kotlin => "Kotlin script",
        FileClass::Scala => "Scala script",
        FileClass::Pdf => "PDF document",
        FileClass::OfficeDoc => "Office document (DOCX)",
        FileClass::OfficeXlsx => "Office spreadsheet (XLSX)",
        FileClass::OfficePptx => "Office presentation (PPTX)",
        FileClass::Odt => "OpenDocument format",
        FileClass::Jpeg => "JPEG image",
        FileClass::Png => "PNG image",
        FileClass::Gif => "GIF image",
        FileClass::Mp4 => "MP4 video",
        FileClass::Mp3 => "MP3 audio",
        FileClass::Zip => "ZIP archive",
        FileClass::Tar => "TAR archive",
        FileClass::Gz => "GZIP compressed",
        FileClass::Rar => "RAR archive",
        FileClass::SevenZip => "7-Zip archive",
        FileClass::Iso => "ISO disk image",
        FileClass::Deb => "Debian package",
        FileClass::Rpm => "RPM package",
        FileClass::Unknown => "Unknown file type",
    }
}

/// Check if a file class is an interpreted language
pub fn is_interpreted(class: &FileClass) -> bool {
    matches!(
        class,
        FileClass::Python
            | FileClass::JavaScript
            | FileClass::TypeScript
            | FileClass::Ruby
            | FileClass::Php
            | FileClass::Perl
            | FileClass::Lua
            | FileClass::Shell
            | FileClass::PowerShell
            | FileClass::R
            | FileClass::Swift
            | FileClass::Kotlin
            | FileClass::Scala
    )
}

/// Check if a file class is a static document (no execution)
pub fn is_static_document(class: &FileClass) -> bool {
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

/// Check if a file class is an archive
pub fn is_archive(class: &FileClass) -> bool {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wasm_magic_detection() {
        let data = b"\x00asm\x01\x00\x00\x00";
        assert_eq!(detect_from_bytes(data), FileClass::Wasm);
    }

    #[test]
    fn test_elf_magic_detection() {
        let data = b"\x7fELF\x02\x01\x01";
        assert_eq!(detect_from_bytes(data), FileClass::Binary);
    }

    #[test]
    fn test_pe_magic_detection() {
        let data = b"MZ\x90\x00\x03\x00";
        assert_eq!(detect_from_bytes(data), FileClass::Binary);
    }

    #[test]
    fn test_pdf_magic_detection() {
        let data = b"%PDF-1.4\n";
        assert_eq!(detect_from_bytes(data), FileClass::Pdf);
    }

    #[test]
    fn test_zip_magic_detection() {
        let data = b"PK\x03\x04\x14\x00\x00\x00";
        assert_eq!(detect_from_bytes(data), FileClass::Zip);
    }

    #[test]
    fn test_png_magic_detection() {
        let data = b"\x89PNG\r\n\x1a\n\x00\x00";
        assert_eq!(detect_from_bytes(data), FileClass::Png);
    }

    #[test]
    fn test_jpeg_magic_detection() {
        let data = b"\xff\xd8\xff\xe0";
        assert_eq!(detect_from_bytes(data), FileClass::Jpeg);
    }

    #[test]
    fn test_gif87a_detection() {
        assert_eq!(detect_from_bytes(b"GIF87a\x00\x00"), FileClass::Gif);
    }

    #[test]
    fn test_gif89a_detection() {
        assert_eq!(detect_from_bytes(b"GIF89a\x00\x00"), FileClass::Gif);
    }

    #[test]
    fn test_gzip_detection() {
        assert_eq!(detect_from_bytes(b"\x1f\x8b\x08\x00"), FileClass::Gz);
    }

    #[test]
    fn test_rar_detection() {
        assert_eq!(detect_from_bytes(b"Rar!\x1a\x07\x00"), FileClass::Rar);
    }

    #[test]
    fn test_7zip_detection() {
        assert_eq!(detect_from_bytes(b"7z\xbc\xaf\x27\x1c"), FileClass::SevenZip);
    }

    #[test]
    fn test_mp3_id3_detection() {
        assert_eq!(detect_from_bytes(b"ID3\x04\x00\x00"), FileClass::Mp3);
    }

    #[test]
    fn test_mp3_sync_word_detection() {
        assert_eq!(detect_from_bytes(b"\xff\xfb\x90\x00"), FileClass::Mp3);
    }

    #[test]
    fn test_java_class_detection() {
        assert_eq!(detect_from_bytes(b"\xCA\xFE\xBA\xBE\x00\x00"), FileClass::JavaClass);
    }

    // Shebang tests
    #[test]
    fn test_shebang_python() {
        assert_eq!(detect_from_bytes(b"#!/usr/bin/env python3\nprint('hi')"), FileClass::Python);
        assert_eq!(detect_from_bytes(b"#!/usr/bin/python\nimport os"), FileClass::Python);
    }

    #[test]
    fn test_shebang_bash() {
        assert_eq!(detect_from_bytes(b"#!/bin/bash\necho hello"), FileClass::Shell);
        assert_eq!(detect_from_bytes(b"#!/bin/sh\necho hello"), FileClass::Shell);
        assert_eq!(detect_from_bytes(b"#!/usr/bin/env bash\necho hello"), FileClass::Shell);
    }

    #[test]
    fn test_shebang_node() {
        assert_eq!(detect_from_bytes(b"#!/usr/bin/env node\nconsole.log('hi')"), FileClass::JavaScript);
    }

    #[test]
    fn test_shebang_ruby() {
        assert_eq!(detect_from_bytes(b"#!/usr/bin/env ruby\nputs 'hi'"), FileClass::Ruby);
    }

    #[test]
    fn test_shebang_perl() {
        assert_eq!(detect_from_bytes(b"#!/usr/bin/perl\nprint 'hi'"), FileClass::Perl);
    }

    // Extension mismatch tests
    #[test]
    fn test_mismatch_random_binary_as_pdf() {
        let path = Path::new("fake_invoice.pdf");
        let detected = FileClass::Binary; // ELF detected from bytes
        let result = check_extension_mismatch(path, &detected);
        assert!(result.is_some());
        let (ext, _desc) = result.unwrap();
        assert_eq!(ext, "pdf");
    }

    #[test]
    fn test_no_mismatch_real_pdf() {
        let path = Path::new("document.pdf");
        let detected = FileClass::Pdf;
        assert!(check_extension_mismatch(path, &detected).is_none());
    }

    #[test]
    fn test_no_extension_no_crash() {
        let path = Path::new("noextension");
        let detected = FileClass::Python;
        assert!(check_extension_mismatch(path, &detected).is_none());
    }

    #[test]
    fn test_zip_docx_not_mismatch() {
        let path = Path::new("report.docx");
        let detected = FileClass::Zip; // ZIP magic from bytes
        assert!(check_extension_mismatch(path, &detected).is_none());
    }

    #[test]
    fn test_unknown_ext_unknown_bytes_no_mismatch() {
        // .xyz maps to Unknown — can't assert mismatch
        let path = Path::new("data.xyz");
        let detected = FileClass::Unknown;
        assert!(check_extension_mismatch(path, &detected).is_none());
    }

    #[test]
    fn test_known_ext_unknown_bytes_is_mismatch() {
        // .pdf maps to Pdf — Unknown bytes means missing %PDF- magic = suspicious
        let path = Path::new("data.pdf");
        let detected = FileClass::Unknown;
        assert!(check_extension_mismatch(path, &detected).is_some());
    }

    #[test]
    fn test_empty_bytes_returns_unknown() {
        assert_eq!(detect_from_bytes(b""), FileClass::Unknown);
    }

    #[test]
    fn test_random_bytes_returns_unknown() {
        assert_eq!(detect_from_bytes(b"\x42\x43\x44\x45\x46"), FileClass::Unknown);
    }

    #[test]
    fn test_extension_mapping() {
        assert_eq!(class_from_extension("wasm"), FileClass::Wasm);
        assert_eq!(class_from_extension("py"), FileClass::Python);
        assert_eq!(class_from_extension("exe"), FileClass::Binary);
        assert_eq!(class_from_extension("PDF"), FileClass::Pdf);
        assert_eq!(class_from_extension("class"), FileClass::JavaClass);
        assert_eq!(class_from_extension("unknown"), FileClass::Unknown);
    }

    #[test]
    fn test_interpreted_detection() {
        assert!(is_interpreted(&FileClass::Python));
        assert!(is_interpreted(&FileClass::JavaScript));
        assert!(!is_interpreted(&FileClass::Wasm));
        assert!(!is_interpreted(&FileClass::Pdf));
    }

    #[test]
    fn test_archive_detection() {
        assert!(is_archive(&FileClass::Zip));
        assert!(is_archive(&FileClass::Tar));
        assert!(!is_archive(&FileClass::Python));
        assert!(!is_archive(&FileClass::Wasm));
    }
}
