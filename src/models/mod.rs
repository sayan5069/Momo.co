use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileRecord {
    pub path: String,
    pub relative_path: String,
    pub hash: String,
    pub size_bytes: u64,
    pub mtime_unix: i64,
    pub language: String,
    pub extension: String,
    pub is_binary: bool,
    pub is_symlink: bool,
    pub permissions: String,
    pub indexed_at: String,
}
