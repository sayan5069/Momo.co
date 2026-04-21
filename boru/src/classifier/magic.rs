//! Magic Bytes Database — File type detection via magic bytes
//!
//! This module contains magic byte signatures for all major file types
//! supported by BORU's universal file classifier.

/// File class categories
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileClass {
    // Executable categories
    Wasm,
    Binary,
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
    // Mach-O (fat binary)
    MagicEntry {
        bytes: b"\xca\xfe\xba\xbe",
        offset: 0,
        class: FileClass::Binary,
        description: "Mach-O fat binary",
    },
    // PE/COFF - Windows executables
    MagicEntry {
        bytes: b"MZ",
        offset: 0,
        class: FileClass::Binary,
        description: "PE executable",
    },
    // PDF documents
    MagicEntry {
        bytes: b"%PDF",
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
        description: "GIF image",
    },
    // GIF89a
    MagicEntry {
        bytes: b"GIF89a",
        offset: 0,
        class: FileClass::Gif,
        description: "GIF image",
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
        description: "MP3 audio",
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

/// Extension to file class mapping
pub fn class_from_extension(ext: &str) -> FileClass {
    match ext.to_lowercase().as_str() {
        "wasm" => FileClass::Wasm,
        // Native binaries — all platforms
        // Windows: exe, dll, scr, msi | Linux: elf, so, bin, out, appimage | macOS: dylib, app, dmg
        "exe" | "dll" | "scr" | "msi" | "bin" | "out" | "elf" | "so" | "appimage" | "dylib" | "app" | "dmg" => FileClass::Binary,
        "py" => FileClass::Python,
        "js" => FileClass::JavaScript,
        "ts" => FileClass::TypeScript,
        "rb" => FileClass::Ruby,
        "php" => FileClass::Php,
        "pl" | "pm" => FileClass::Perl,
        "lua" => FileClass::Lua,
        "sh" | "bash" => FileClass::Shell,
        "zsh" => FileClass::Shell,
        "fish" => FileClass::Shell,
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

/// Detect file class from magic bytes
pub fn class_from_magic_bytes(data: &[u8]) -> Option<FileClass> {
    for entry in MAGIC_DATABASE {
        let end = entry.offset + entry.bytes.len();
        if data.len() >= end && &data[entry.offset..end] == entry.bytes {
            return Some(entry.class.clone());
        }
    }
    None
}

/// Get human-readable description for a file class
pub fn class_description(class: &FileClass) -> &'static str {
    match class {
        FileClass::Wasm => "WebAssembly module",
        FileClass::Binary => "Native binary executable",
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
        assert_eq!(class_from_magic_bytes(data), Some(FileClass::Wasm));
    }

    #[test]
    fn test_elf_magic_detection() {
        let data = b"\x7fELF\x02\x01\x01";
        assert_eq!(class_from_magic_bytes(data), Some(FileClass::Binary));
    }

    #[test]
    fn test_pdf_magic_detection() {
        let data = b"%PDF-1.4\n";
        assert_eq!(class_from_magic_bytes(data), Some(FileClass::Pdf));
    }

    #[test]
    fn test_zip_magic_detection() {
        let data = b"PK\x03\x04\x14\x00\x00\x00";
        assert_eq!(class_from_magic_bytes(data), Some(FileClass::Zip));
    }

    #[test]
    fn test_extension_mapping() {
        assert_eq!(class_from_extension("wasm"), FileClass::Wasm);
        assert_eq!(class_from_extension("py"), FileClass::Python);
        assert_eq!(class_from_extension("exe"), FileClass::Binary);
        assert_eq!(class_from_extension("PDF"), FileClass::Pdf);
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
